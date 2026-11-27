"""
WSGI entry-point for PhishTrace AI.
Provides clean import resolution for Gunicorn on hosting platforms (Render, etc.).
"""
import os
import sys
import importlib.util
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Safely load the Flask application instance from app.py without collision with the app/ package
_spec = importlib.util.spec_from_file_location("main_flask_app", ROOT_DIR / "app.py")
_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)

app = _module.app
application = app  # Standard WSGI alias

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    host = "0.0.0.0" if (os.getenv("RENDER") or os.getenv("APP_ENV") == "production") else "127.0.0.1"
    app.run(host=host, port=port)
