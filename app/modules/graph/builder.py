"""
Threat Relationship Graph Builder.
Correlates URL, Hostname, Registrable Domain, IP addresses,
Registrar, Nameservers, and Target Brands into an interconnected graph
with risk scoring and threat indicators.
"""
from urllib.parse import urlparse
from typing import Any

from app.modules.url_features.extractor import URLFeatures
from app.modules.brand_detector.detector import BrandMatch
from app.modules.graph.models import ThreatGraph, GraphNode, GraphEdge
from app.modules.graph.dns_resolver import resolve_host_infrastructure
from app.modules.graph.whois_rdap import get_domain_registration_info


def build_threat_graph(
    features: URLFeatures,
    brand_match: BrandMatch,
    skip_network_calls: bool = False,
) -> ThreatGraph:
    """
    Constructs the Threat Relationship Graph for a given URL and its extracted features.
    Handles network failures gracefully without halting graph generation.
    """
    parsed = urlparse(features.url)
    hostname = parsed.hostname or features.domain
    domain = features.domain

    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []
    threat_indicators: list[str] = []

    # 1. Root URL Node
    url_risk = "suspicious" if features.suspicious_keyword_count > 0 else "neutral"
    if features.has_ip_address_host or features.has_at_symbol:
        url_risk = "high"
    nodes.append(
        GraphNode(
            id="node:url",
            label=features.url if len(features.url) <= 38 else f"{features.url[:35]}…",
            type="url",
            risk_level=url_risk,
            properties={
                "full_url": features.url,
                "scheme": parsed.scheme,
                "path": parsed.path or "/",
                "is_https": features.is_https,
                "keywords": features.suspicious_keywords_found,
            },
        )
    )

    # 2. Hostname Node
    host_risk = "high" if features.has_ip_address_host else "neutral"
    if features.num_subdomains >= 3:
        host_risk = "suspicious"
    host_node_id = f"node:host:{hostname}"
    nodes.append(
        GraphNode(
            id=host_node_id,
            label=hostname,
            type="hostname",
            risk_level=host_risk,
            properties={
                "subdomain": features.subdomain,
                "num_subdomains": features.num_subdomains,
                "is_raw_ip": features.has_ip_address_host,
            },
        )
    )

    edges.append(
        GraphEdge(
            id="edge:url-host",
            source="node:url",
            target=host_node_id,
            relationship="CONTAINS_HOST",
            label="Hosts",
        )
    )

    # 3. DNS Resolution & IP Nodes
    dns_data: dict[str, Any] = {"resolved": False, "ips": [], "ssrf_risk": False, "is_fast_flux": False}
    if not skip_network_calls:
        dns_data = resolve_host_infrastructure(hostname)

    if dns_data.get("ssrf_risk"):
        threat_indicators.append("SSRF Risk: Hostname resolves to private, loopback, or link-local address.")
    if dns_data.get("is_fast_flux"):
        threat_indicators.append("Fast-Flux DNS Indicator: Host maps to 4 or more IP addresses in a single query.")

    for i, ip_info in enumerate(dns_data.get("ips", [])):
        ip_str = ip_info["ip"]
        ip_node_id = f"node:ip:{ip_str}"

        ip_risk = "low"
        if ip_info["is_private"] or ip_info["is_loopback"] or ip_info["is_link_local"]:
            ip_risk = "critical"
        elif dns_data.get("is_fast_flux"):
            ip_risk = "high"
        elif features.has_ip_address_host:
            ip_risk = "high"

        nodes.append(
            GraphNode(
                id=ip_node_id,
                label=ip_str,
                type="ip",
                risk_level=ip_risk,
                properties={
                    "ip": ip_str,
                    "version": f"IPv{ip_info.get('version', 4)}",
                    "is_private": ip_info.get("is_private", False),
                    "is_loopback": ip_info.get("is_loopback", False),
                    "is_link_local": ip_info.get("is_link_local", False),
                    "reverse_host": ip_info.get("reverse_host"),
                },
            )
        )

        edges.append(
            GraphEdge(
                id=f"edge:host-ip-{i}",
                source=host_node_id,
                target=ip_node_id,
                relationship="RESOLVES_TO",
                label="Resolves to",
            )
        )

    # 4. Registrable Domain Node & RDAP WHOIS
    rdap_info = None
    if not skip_network_calls and domain and not features.has_ip_address_host:
        rdap_info = get_domain_registration_info(domain)

    domain_risk = "neutral"
    domain_props: dict[str, Any] = {
        "domain": domain,
        "sld": features.sld,
        "suffix": features.suffix,
    }

    if rdap_info and rdap_info.available:
        domain_props.update({
            "age_days": rdap_info.age_days,
            "created_date": rdap_info.created_date,
            "expiration_date": rdap_info.expiration_date,
            "registrar": rdap_info.registrar,
            "status_codes": rdap_info.status_codes,
        })

        if rdap_info.is_critically_young:
            domain_risk = "critical"
            threat_indicators.append(
                f"Critically Young Domain: Registered only {rdap_info.age_days} days ago (< 14 days). "
                "Strong indicator of ephemeral phishing infrastructure."
            )
        elif rdap_info.is_recently_registered:
            domain_risk = "high"
            threat_indicators.append(
                f"Recently Registered Domain: Registered {rdap_info.age_days} days ago (< 30 days)."
            )
        elif rdap_info.age_days and rdap_info.age_days > 730:
            domain_risk = "safe"

    domain_node_id = f"node:domain:{domain}"
    nodes.append(
        GraphNode(
            id=domain_node_id,
            label=domain,
            type="domain",
            risk_level=domain_risk,
            properties=domain_props,
        )
    )

    if hostname != domain:
        edges.append(
            GraphEdge(
                id="edge:host-domain",
                source=host_node_id,
                target=domain_node_id,
                relationship="SUBDOMAIN_OF",
                label="Subdomain of",
            )
        )

    # 5. Registrar Node
    if rdap_info and rdap_info.available and rdap_info.registrar:
        reg_id = f"node:registrar:{rdap_info.registrar}"
        nodes.append(
            GraphNode(
                id=reg_id,
                label=rdap_info.registrar,
                type="registrar",
                risk_level="neutral",
                properties={"registrar": rdap_info.registrar},
            )
        )
        edges.append(
            GraphEdge(
                id="edge:domain-registrar",
                source=domain_node_id,
                target=reg_id,
                relationship="REGISTERED_WITH",
                label="Registered with",
            )
        )

    # 6. Nameserver Nodes (limit to first 3 to prevent graph overcrowding)
    if rdap_info and rdap_info.available and rdap_info.nameservers:
        for i, ns in enumerate(rdap_info.nameservers[:3]):
            ns_id = f"node:ns:{ns}"
            nodes.append(
                GraphNode(
                    id=ns_id,
                    label=ns,
                    type="nameserver",
                    risk_level="neutral",
                    properties={"nameserver": ns},
                )
            )
            edges.append(
                GraphEdge(
                    id=f"edge:domain-ns-{i}",
                    source=domain_node_id,
                    target=ns_id,
                    relationship="DELEGATED_TO",
                    label="Delegated to",
                )
            )

    # 7. Brand Target Node (if brand impersonation detected)
    if brand_match.detected_brand:
        brand_id = f"node:brand:{brand_match.canonical_domain or 'target'}"
        brand_risk = "critical" if brand_match.impersonation_risk == "HIGH" else "high"
        nodes.append(
            GraphNode(
                id=brand_id,
                label=f"Target: {brand_match.detected_brand}",
                type="brand_target",
                risk_level=brand_risk,
                properties={
                    "target_brand": brand_match.detected_brand,
                    "similarity_score": brand_match.similarity_score,
                    "technique": brand_match.technique,
                    "impersonation_risk": brand_match.impersonation_risk,
                },
            )
        )
        edges.append(
            GraphEdge(
                id="edge:domain-brand",
                source=domain_node_id,
                target=brand_id,
                relationship="TARGETS_BRAND",
                label=f"Targets Brand ({brand_match.technique or 'Similarity'})",
            )
        )
        threat_indicators.append(
            f"Brand Impersonation: Target brand '{brand_match.detected_brand}' "
            f"identified with {brand_match.similarity_score:.0%} similarity ({brand_match.technique})."
        )

    # General feature flags
    if features.has_ip_address_host:
        threat_indicators.append("Host Obfuscation: Direct IP address host masks destination identity.")
    if features.uses_url_shortener:
        threat_indicators.append("Redirect Obfuscation: Known URL shortening service conceals destination.")
    if features.has_at_symbol:
        threat_indicators.append("Credential/Host Obfuscation: '@' character used to mislead URL destination.")

    summary = {
        "total_nodes": len(nodes),
        "total_edges": len(edges),
        "domain": domain,
        "domain_age_days": rdap_info.age_days if (rdap_info and rdap_info.available) else None,
        "is_recently_registered": rdap_info.is_recently_registered if (rdap_info and rdap_info.available) else False,
        "is_critically_young": rdap_info.is_critically_young if (rdap_info and rdap_info.available) else False,
        "registrar": rdap_info.registrar if (rdap_info and rdap_info.available) else None,
        "nameservers": rdap_info.nameservers if (rdap_info and rdap_info.available) else [],
        "resolved_ips": [ip["ip"] for ip in dns_data.get("ips", [])],
        "dns_resolved": dns_data.get("resolved", False),
        "ssrf_risk": dns_data.get("ssrf_risk", False),
        "is_fast_flux": dns_data.get("is_fast_flux", False),
    }

    return ThreatGraph(
        nodes=nodes,
        edges=edges,
        summary=summary,
        threat_indicators=threat_indicators,
    )
