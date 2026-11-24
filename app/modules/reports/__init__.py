"""
Forensic Investigation Reports module.
Generates structured JSON and printable HTML forensic investigation reports
with SHA-256 integrity hashes for cybersecurity incident response.
"""
from app.modules.reports.generator import generate_investigation_report_html, generate_investigation_report_json

__all__ = ["generate_investigation_report_html", "generate_investigation_report_json"]
