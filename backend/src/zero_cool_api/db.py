"""Database engine and session helpers (SQLAlchemy + SQLite)."""

import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from zero_cool_api.models import Base

DEFAULT_DATABASE_PATH = "data/zero_cool.db"


def get_database_path() -> Path:
    """Read the SQLite file location from the environment.

    Returns:
        The path in ``DATABASE_PATH``, or ``data/zero_cool.db`` when unset.
    """
    return Path(os.environ.get("DATABASE_PATH", DEFAULT_DATABASE_PATH))


def create_db_engine(path: Path | None = None) -> Engine:
    """Create an engine for a SQLite file, creating its directory if needed.

    Parameters:
        path: Database file. Defaults to :func:`get_database_path`.

    Returns:
        An engine that enforces foreign keys on every connection.

    Raises:
        OSError: If the parent directory cannot be created.
    """
    db_path = path or get_database_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(f"sqlite:///{db_path}")

    @event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_conn: Any, _record: Any) -> None:
        # SQLite ignores foreign keys unless enabled per connection.
        dbapi_conn.execute("PRAGMA foreign_keys = ON")

    return engine


def init_db(engine: Engine) -> None:
    """Create all tables that do not exist yet.

    Parameters:
        engine: Engine of the target database.
    """
    Base.metadata.create_all(engine)


def get_session() -> Iterator[Session]:
    """FastAPI dependency yielding a session bound to the configured database.

    Yields:
        A session that is closed when the request ends.
    """
    engine = create_db_engine()
    init_db(engine)
    with sessionmaker(engine)() as session:
        yield session
