# PhishTrace AI — Local Flask Application

PhishTrace AI is a local-first phishing investigation dashboard. The supported entry point in this package is the **Flask app in `app.py`**, which serves the HTML/CSS/JavaScript dashboard from `templates/` and `static/`.

## Features

- URL analysis using lexical features, brand-impersonation checks, an ML model, optional VirusTotal reputation, and infrastructure metadata.
- Email (`.eml`) parsing with extracted URL analysis.
- File hashing (MD5, SHA-1, SHA-256) for investigation reference.
- Risk score, evidence, relationship graph, adversarial mutation tests, history, and report exports.
- SQLite persistence by default.

**Important limitations:**
- File uploads are hashed only. A malware scanner is not configured by default, so file hashing does not prove a file is safe.
- The bundled ML model was trained using synthetic/mock data. Treat its prediction as experimental until it is retrained and validated on a representative real dataset.
- VirusTotal checks require a valid `VIRUSTOTAL_API_KEY` and an internet connection. Without it, the rest of the analysis continues without that signal.
- Domain/DNS enrichment may be unavailable offline. Automated results are indicators, not a guarantee of safety.
- The included alternate `backend/` and `frontend/` directories are older/experimental implementations and are **not** used by the supported Flask dashboard. Start only the root `app.py` unless you intentionally work on those alternate code paths.

## Requirements

- Python 3.11 or newer (Python 3.12 recommended if all pinned packages support it)
- Internet access to install Python dependencies; internet access at runtime is optional except for external threat-intelligence enrichment.

## Run on Windows

Open PowerShell in this folder:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
python app.py
```

If PowerShell blocks activation, use the virtual environment's interpreter directly:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

## Run on macOS/Linux

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
cp .env.example .env
python app.py
```

Open **http://127.0.0.1:5000**. The application intentionally binds to loopback and rejects non-loopback requests because this build does not include user accounts or authentication. Do not expose it directly to the internet or a LAN. A public deployment needs authentication, per-user record authorization, CSRF protection, production WSGI hosting, HTTPS, and deployment-specific network controls.

## Configuration

Copy `.env.example` to `.env`. Keep real keys in `.env`; never commit it or share it publicly.

- `PORT`: local port (default `5000`)
- `HOST`: must remain `127.0.0.1` for this local-only build
- `APP_ENV`: use `development` locally; production deployment requires additional security work
- `SECRET_KEY`: leave blank for a randomly generated local key, or set a private random value
- `VIRUSTOTAL_API_KEY`: optional VirusTotal v3 API key
- `DATABASE_URL`: optional SQLAlchemy database URL; defaults to `data/phishtrace.db`
- `MAX_CONTENT_LENGTH`: maximum request size in bytes (default 10,485,760 / 10 MiB)

## Tests and checks

Install dependencies first, then run:

```bash
python -m compileall -q app app.py tests
node --check static/js/app.js
python -m pytest -q
```

Tests that use external services may need network access. The project intentionally does not run live VirusTotal requests as part of unit tests.

## Security notes

- The server is local-only by design and debug mode is disabled.
- URL normalization rejects non-HTTP(S) schemes, embedded credentials, malformed ports, whitespace/control characters, and excessively long inputs. URL analysis does not fetch the submitted URL itself.
- Requests and uploads are capped at 10 MiB by default.
- Uploaded files are not executed. File analysis computes hashes only unless a malware-scanning service is separately configured.
- Report values are HTML-escaped before rendering.
- Do not add live user data or secrets to test fixtures. The history-clear endpoint permanently deletes local scan history; use it intentionally.
