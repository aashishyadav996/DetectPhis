import email
from email.policy import default
import re

# Simple regex to find URLs in text
URL_REGEX = re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w.-]*')

def analyze_email(file_content: bytes) -> dict:
    """
    Parses a raw .eml file byte string and extracts headers and URLs.
    """
    msg = email.message_from_bytes(file_content, policy=default)
    
    # Extract headers
    headers = {
        "subject": msg.get("Subject", "(No Subject)"),
        "from": msg.get("From", ""),
        "to": msg.get("To", ""),
        "date": msg.get("Date", ""),
        "message_id": msg.get("Message-ID", ""),
        "authentication_results": msg.get("Authentication-Results", "")
    }
    
    # Extract body
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            cdispo = str(part.get('Content-Disposition'))
            # Get text/plain or text/html content
            if (ctype == 'text/plain' or ctype == 'text/html') and 'attachment' not in cdispo:
                payload = part.get_payload(decode=True)
                if payload:
                    body += payload.decode('utf-8', errors='ignore')
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body = payload.decode('utf-8', errors='ignore')
        
    # Extract URLs
    urls = list(set(URL_REGEX.findall(body)))
    
    return {
        "headers": headers,
        "extracted_urls": urls,
        "body_preview": body[:1000] + ("..." if len(body) > 1000 else "")
    }
