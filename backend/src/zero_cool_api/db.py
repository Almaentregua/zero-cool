"""SQLite connection helpers."""

import os
import sqlite3
from pathlib import Path

DEFAULT_DATABASE_PATH = "data/zero_cool.db"


def get_database_path() -> Path:
    """Read the SQLite file location from the environment.

    Returns:
        The path in ``DATABASE_PATH``, or ``data/zero_cool.db`` when unset.
    """
    return Path(os.environ.get("DATABASE_PATH", DEFAULT_DATABASE_PATH))


def connect(path: Path | None = None) -> sqlite3.Connection:
    """Open a SQLite connection, creating the parent directory if needed.

    Parameters:
        path: Database file. Defaults to :func:`get_database_path`.

    Returns:
        An open connection with foreign keys enforced and rows accessible by name.

    Raises:
        sqlite3.Error: If the database cannot be opened.
        OSError: If the parent directory cannot be created.
    """
    db_path = path or get_database_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    # SQLite does not enforce foreign keys unless asked, per connection.
    conn.execute("PRAGMA foreign_keys = ON")
    return conn
