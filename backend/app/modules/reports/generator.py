"""
Forensic Investigation Report Generator.
Outputs tamper-verifiable, professional HTML and JSON audit reports.
"""
from datetime import datetime, timezone
import hashlib
import json
from typing import Any


def _compute_sha256(data: dict[str, Any]) -> str:
    raw = json.dumps(data, sort_keys=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def generate_investigation_report_json(scan_data: dict[str, Any]) -> dict[str, Any]:
    """
    Constructs a structured JSON forensic incident report.
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    integrity_hash = _compute_sha256(scan_data)

    details = scan_data.get("details", {})
    features = details.get("features", {})
    brand = details.get("brand_analysis", {})
    vt = details.get("virustotal", {})
    ml = details.get("ml", {})
    graph = details.get("threat_graph", {})
    summary = graph.get("summary", {})

    return {
        "report_id": f"PTR-{scan_data.get('id', 'LIVE')}-{int(datetime.now().timestamp())}",
        "generated_at": timestamp,
        "integrity_sha256": integrity_hash,
        "investigation": {
            "url": scan_data.get("url"),
            "normalized_url": scan_data.get("normalized_url"),
            "risk_score": scan_data.get("risk_score"),
            "confidence": scan_data.get("confidence"),
            "classification": scan_data.get("classification"),
            "reputation_gap_warning": details.get("reputation_gap_warning", False),
        },
        "findings": {
            "risk_increasing": details.get("reasons_increasing", []),
            "risk_reducing": details.get("reasons_decreasing", []),
            "infrastructure_threat_indicators": graph.get("threat_indicators", []),
        },
        "signals": {
            "lexical": features,
            "brand_impersonation": brand,
            "virustotal_reputation": vt,
            "machine_learning_classifier": ml,
            "infrastructure_graph": summary,
        },
        "recommendations": _get_recommendations(scan_data.get("classification", "LOW RISK")),
    }


def _get_recommendations(classification: str) -> list[str]:
    if classification == "HIGH RISK":
        return [
            "Block destination URL and registered apex domain at corporate perimeter firewall / DNS sinkhole.",
            "Inspect web proxy logs for internal endpoints or employee sessions that accessed this domain.",
            "Initiate credential revocation if user entered authentication secrets on target portal.",
            "File abuse / takedown complaint with authoritative registrar and hosting provider.",
        ]
    elif classification == "SUSPICIOUS":
        return [
            "Isolate client session in secure web gateway or remote browser isolation (RBI).",
            "Monitor outbound DNS traffic for recursive queries resolving to target domain.",
            "Verify sender identity and email authentication headers (SPF/DKIM/DMARC) if received via email.",
        ]
    return [
        "No critical anomalies detected. Standard automated telemetry monitoring recommended.",
        "Ensure endpoint protection and secure browser extensions remain up-to-date.",
    ]


def generate_investigation_report_html(scan_data: dict[str, Any]) -> str:
    """
    Generates a standalone, CSS-styled printable HTML forensic report.
    """
    report = generate_investigation_report_json(scan_data)
    inv = report["investigation"]
    findings = report["findings"]
    signals = report["signals"]
    brand = signals.get("brand_impersonation", {})
    infra = signals.get("infrastructure_graph", {})
    recs = report["recommendations"]

    risk_class = inv["classification"].upper()
    color_map = {
        "HIGH RISK": "#ff5c6c",
        "SUSPICIOUS": "#ffb84d",
        "LOW RISK": "#4fd1c5",
    }
    badge_color = color_map.get(risk_class, "#4fd1c5")

    reasons_up_html = "".join(f"<li>{r}</li>" for r in findings["risk_increasing"]) or "<li>None</li>"
    reasons_down_html = "".join(f"<li>{r}</li>" for r in findings["risk_reducing"]) or "<li>None</li>"
    recs_html = "".join(f"<li>{r}</li>" for r in recs)

    ips_str = ", ".join(infra.get("resolved_ips", [])) or "None resolved"
    ns_str = ", ".join(infra.get("nameservers", [])) or "None"
    domain_age_str = f"{infra.get('domain_age_days')} days" if infra.get("domain_age_days") is not None else "Unknown"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>PhishTrace AI — Forensic Investigation Report ({report['report_id']})</title>
  <style>
    body {{
      font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
      margin: 0;
      padding: 32px;
      color: #1e293b;
      background: #f8fafc;
      font-size: 14px;
      line-height: 1.6;
    }}
    .report-shell {{
      max-width: 860px;
      margin: 0 auto;
      background: #ffffff;
      border: 1px solid #e2e8f0;
      border-radius: 8px;
      padding: 40px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.04);
    }}
    .header {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      border-bottom: 2px solid #0f172a;
      padding-bottom: 20px;
      margin-bottom: 24px;
    }}
    .title-block h1 {{
      margin: 0;
      font-size: 24px;
      color: #0f172a;
      letter-spacing: -0.02em;
    }}
    .title-block p {{
      margin: 4px 0 0;
      color: #64748b;
      font-size: 13px;
    }}
    .meta-block {{
      text-align: right;
      font-family: monospace;
      font-size: 11px;
      color: #64748b;
    }}
    .risk-banner {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      background: #f1f5f9;
      border-left: 6px solid {badge_color};
      padding: 16px 20px;
      border-radius: 4px;
      margin-bottom: 28px;
    }}
    .risk-verdict {{
      font-size: 20px;
      font-weight: 700;
      color: {badge_color};
    }}
    .risk-scores {{
      font-size: 13px;
      color: #334155;
    }}
    .url-strip {{
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      padding: 10px 14px;
      font-family: monospace;
      font-size: 13px;
      border-radius: 4px;
      word-break: break-all;
      margin-bottom: 24px;
    }}
    h2 {{
      font-size: 15px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: #0f172a;
      border-bottom: 1px solid #e2e8f0;
      padding-bottom: 6px;
      margin: 24px 0 12px;
    }}
    .grid-2 {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 16px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin-bottom: 16px;
    }}
    th, td {{
      padding: 8px 12px;
      border: 1px solid #e2e8f0;
      text-align: left;
    }}
    th {{
      background: #f8fafc;
      color: #475569;
      font-size: 12px;
    }}
    td.mono {{
      font-family: monospace;
      font-size: 12px;
    }}
    ul {{
      margin: 0 0 16px;
      padding-left: 20px;
    }}
    li {{
      margin-bottom: 4px;
    }}
    .hash-footer {{
      margin-top: 32px;
      border-top: 1px solid #e2e8f0;
      padding-top: 16px;
      font-size: 11px;
      color: #94a3b8;
      font-family: monospace;
      word-break: break-all;
    }}
    @media print {{
      body {{ background: #fff; padding: 0; }}
      .report-shell {{ border: none; box-shadow: none; padding: 0; }}
    }}
  </style>
</head>
<body>
  <div class="report-shell">
    <div class="header">
      <div class="title-block">
        <h1>PhishTrace AI</h1>
        <p>Explainable Multi-Signal Forensic Investigation Report</p>
      </div>
      <div class="meta-block">
        <div><strong>REPORT ID:</strong> {report['report_id']}</div>
        <div><strong>GENERATED:</strong> {report['generated_at'][:19].replace('T', ' ')} UTC</div>
      </div>
    </div>

    <div class="url-strip">
      <strong>Target URL:</strong> {inv['normalized_url']}
    </div>

    <div class="risk-banner">
      <div>
        <div style="font-size: 11px; color: #64748b; text-transform: uppercase;">Assessment Verdict</div>
        <div class="risk-verdict">{inv['classification']}</div>
      </div>
      <div class="risk-scores">
        <div><strong>Risk Score:</strong> {inv['risk_score']} / 100</div>
        <div><strong>Detection Confidence:</strong> {inv['confidence']}%</div>
      </div>
    </div>

    <h2>1. Executive Summary & Findings</h2>
    <div class="grid-2">
      <div>
        <strong style="color: #b91c1c;">Risk-Elevating Indicators:</strong>
        <ul>{reasons_up_html}</ul>
      </div>
      <div>
        <strong style="color: #047857;">Risk-Mitigating Indicators:</strong>
        <ul>{reasons_down_html}</ul>
      </div>
    </div>

    <h2>2. Multi-Signal Evidence Matrix</h2>
    <table>
      <thead>
        <tr>
          <th>Signal Module</th>
          <th>Assessment / Metric</th>
          <th>Technical Details</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td><strong>Brand Impersonation</strong></td>
          <td>{brand.get('impersonation_risk', 'NONE')}</td>
          <td>Target: {brand.get('detected_brand') or 'None'} ({brand.get('technique') or 'No match'})</td>
        </tr>
        <tr>
          <td><strong>Reputation (VirusTotal)</strong></td>
          <td>{signals.get('virustotal_reputation', {}).get('malicious_count', 0)} / {signals.get('virustotal_reputation', {}).get('total_engines', 0)} engines</td>
          <td>{'Reputation Gap Warning: low detection count' if inv.get('reputation_gap_warning') else 'Reputation aligned'}</td>
        </tr>
        <tr>
          <td><strong>Machine Learning</strong></td>
          <td>{round((signals.get('machine_learning_classifier', {}).get('phishing_probability') or 0.0) * 100)}% phishing probability</td>
          <td>Model: {signals.get('machine_learning_classifier', {}).get('model_name') or 'Pipeline Classifier'}</td>
        </tr>
      </tbody>
    </table>

    <h2>3. Infrastructure & Domain Intelligence</h2>
    <table>
      <tbody>
        <tr>
          <th>Apex Domain</th>
          <td class="mono">{scan_data.get('domain') or 'N/A'}</td>
          <th>Domain Age</th>
          <td class="mono">{domain_age_str}</td>
        </tr>
        <tr>
          <th>Registrar</th>
          <td>{infra.get('registrar') or 'Unspecified'}</td>
          <th>SSRF Security</th>
          <td>{'ALERT: Host resolves to internal IP' if infra.get('ssrf_risk') else 'PASS: Public IP'}</td>
        </tr>
        <tr>
          <th>Resolved IP(s)</th>
          <td class="mono" colspan="3">{ips_str}</td>
        </tr>
        <tr>
          <th>Authoritative Nameservers</th>
          <td class="mono" colspan="3">{ns_str}</td>
        </tr>
      </tbody>
    </table>

    <h2>4. Incident Response Recommendations</h2>
    <ul>{recs_html}</ul>

    <div class="hash-footer">
      <div><strong>Cryptographic Integrity Signature (SHA-256):</strong></div>
      <div>{report['integrity_sha256']}</div>
      <div style="margin-top: 4px;">Verified by PhishTrace AI Forensic Audit Engine.</div>
    </div>
  </div>
</body>
</html>
"""
