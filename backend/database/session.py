from __future__ import annotations

import os

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session, sessionmaker

from database.tables import Base


def _database_url() -> str:
    return os.getenv("DATABASE_URL", "sqlite:///./ddos_app.db")


DATABASE_URL = _database_url()

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, class_=Session)


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    _run_lightweight_migrations()


def _run_lightweight_migrations() -> None:
    if not DATABASE_URL.startswith("sqlite"):
        return

    inspector = inspect(engine)
    if not inspector.has_table("csv_sample_rows"):
        return

    existing = {col["name"] for col in inspector.get_columns("csv_sample_rows")}
    if "full_csv" not in existing:
        with engine.begin() as conn:
            conn.execute(
                text("ALTER TABLE csv_sample_rows ADD COLUMN full_csv TEXT")
            )
