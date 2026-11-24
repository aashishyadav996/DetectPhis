import hashlib
import os

def analyze_file(file_content: bytes, filename: str) -> dict:
    """
    Computes hashes for a generic file and returns a standard analysis payload.
    """
    # Compute hashes
    md5 = hashlib.md5(file_content).hexdigest()
    sha1 = hashlib.sha1(file_content).hexdigest()
    sha256 = hashlib.sha256(file_content).hexdigest()
    
    ext = os.path.splitext(filename)[1].lower()
    
    return {
        "filename": filename,
        "size_bytes": len(file_content),
        "extension": ext,
        "hashes": {
            "md5": md5,
            "sha1": sha1,
            "sha256": sha256
        },
        # Risk assessment placeholders until connected to VirusTotal API for files
        "risk_score": 0.0,
        "classification": "unknown",
        "message": "File analysis completed. (VT file integration pending)"
    }
