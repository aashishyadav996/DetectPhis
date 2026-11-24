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
    
    # Report only a basename; never echo a client-supplied path back as a path.
    safe_filename = os.path.basename(str(filename).replace("\\", "/"))[:255] or "uploaded-file"
    ext = os.path.splitext(safe_filename)[1].lower()
    
    return {
        "filename": safe_filename,
        "size_bytes": len(file_content),
        "extension": ext,
        "hashes": {
            "md5": md5,
            "sha1": sha1,
            "sha256": sha256
        },
        # Risk assessment placeholders until connected to VirusTotal API for files
        "risk_score": None,
        "classification": "NOT_SCANNED",
        "message": "File hashes calculated only. No malware scanner is configured, so this result does not establish that the file is safe."
    }
