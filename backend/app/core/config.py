"""
Central app configuration, loaded from environment variables.
Keeps secrets and settings out of source code, per project security requirements.
"""
import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    app_env: str = os.getenv("APP_ENV", "development")
    cors_origins: list[str] = os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",")

    # Placeholders for later phases — intentionally unset until those
    # modules are actually implemented, so nothing silently pretends to work.
    virustotal_api_key: str | None = os.getenv("VIRUSTOTAL_API_KEY")
    database_url: str | None = os.getenv("DATABASE_URL")
    jwt_secret: str | None = os.getenv("JWT_SECRET")


settings = Settings()
