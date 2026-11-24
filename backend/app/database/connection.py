"""
Database connection and engine configuration.
"""
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from app.core.config import settings
from app.database.models import Base

# Ensure local data directory exists for SQLite
DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
DEFAULT_SQLITE_URL = f"sqlite:///{DATA_DIR / 'phishtrace.db'}"

raw_db_url = settings.database_url or DEFAULT_SQLITE_URL
if raw_db_url.startswith("postgres://"):
    raw_db_url = raw_db_url.replace("postgres://", "postgresql://", 1)

connect_args = {"check_same_thread": False} if raw_db_url.startswith("sqlite") else {}

engine = create_engine(
    raw_db_url,
    connect_args=connect_args,
    echo=False,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db() -> None:
    """Creates database tables if they do not already exist."""
    Base.metadata.create_all(bind=engine)


def get_db():
    """Returns a new database session. Caller is responsible for closing it."""
    return SessionLocal()
