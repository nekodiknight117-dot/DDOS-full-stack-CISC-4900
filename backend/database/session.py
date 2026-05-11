"""SQLAlchemy engine/session helpers.

This project currently uses SQLAlchemy ORM models in `database.tables` but did not
wire up an engine/session. We default to a local SQLite DB for development.
"""

from __future__ import annotations

import os

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from database.tables import Base


def _database_url() -> str:
    # Allow override via env var (e.g. Postgres URL) while keeping a working default.
    return os.getenv("DATABASE_URL", "sqlite:///./ddos_app.db")


DATABASE_URL = _database_url()

engine = create_engine(
    DATABASE_URL,
    # SQLite needs this for use across threads (uvicorn reload / FastAPI deps).
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, class_=Session)


def init_db() -> None:
    """Create tables if they don't exist."""
    Base.metadata.create_all(bind=engine)

