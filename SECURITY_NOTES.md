# Security Notes — PhishTrace AI

## What this repair changes

- The supported Flask app starts on `127.0.0.1` with debug mode disabled.
- Non-loopback client requests are rejected. This build does not include user accounts, per-user authorization, or authenticated investigator access, so it must not be exposed to a LAN or the public internet.
- Cross-origin CORS access is no longer enabled globally.
- Responses include browser security headers and a restrictive Content Security Policy.
- Requests/uploads are limited to 10 MiB by default.
- JSON request shapes and URL input types are validated.
- URL normalization rejects unsupported schemes, embedded credentials, malformed ports, control/space characters, and overlong input. URL scanning currently analyzes URL text and domain metadata; it does not load the submitted webpage.
- Report fields are HTML-escaped before they are inserted into report markup.
- Unexpected API errors are logged locally and return generic client-facing messages.
- File hashing is clearly labeled as hashing-only; no malware verdict is generated without a configured scanner.
- Database report tests use a temporary test database instead of clearing the user's scan history.

## Remaining limitations

- No application can be guaranteed to have zero bugs or be impossible to hack.
- Public deployment is not supported until authentication, authorization, CSRF protection, production WSGI serving, HTTPS, and deployment-specific network controls are implemented and tested.
- URL, email, and file results are heuristic or service-dependent and must not be treated as proof that content is safe.
- The bundled ML model was trained on synthetic data and is experimental.
- VirusTotal live API integration was not verified in this sandbox.
- The current environment could not install missing packages because network/package-index access was unavailable. Full application startup and the full test suite therefore still need to be verified on a machine with dependencies installed.
