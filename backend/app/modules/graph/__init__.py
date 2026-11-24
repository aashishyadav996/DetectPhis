"""
Threat Relationship Investigation Graph module.
Provides DNS resolution, WHOIS/RDAP infrastructure analysis, and
graph correlation of domains, IPs, registrars, and brand targets.
"""
from app.modules.graph.models import ThreatGraph, GraphNode, GraphEdge
from app.modules.graph.builder import build_threat_graph
from app.modules.graph.dns_resolver import resolve_host_infrastructure
from app.modules.graph.whois_rdap import get_domain_registration_info, DomainRegistrationInfo

__all__ = [
    "build_threat_graph",
    "ThreatGraph",
    "GraphNode",
    "GraphEdge",
    "resolve_host_infrastructure",
    "get_domain_registration_info",
    "DomainRegistrationInfo",
]
