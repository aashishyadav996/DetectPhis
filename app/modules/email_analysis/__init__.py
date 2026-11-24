"""
Email analysis module.
Provides full .eml email file parsing and direct email address (Email ID) investigation.
"""
from app.modules.email_analysis.parser import analyze_email
from app.modules.email_analysis.investigator import investigate_email_address

__all__ = ["analyze_email", "investigate_email_address"]
