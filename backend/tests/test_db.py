"""Tests for the SQLite helpers."""

from pathlib import Path

import pytest

from zero_cool_api.db import connect, get_database_path


def test_database_path_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DATABASE_PATH", raising=False)
    assert get_database_path() == Path("data/zero_cool.db")


def test_database_path_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_PATH", "/tmp/x.db")  # noqa: S108
    assert get_database_path() == Path("/tmp/x.db")  # noqa: S108


def test_connect_creates_directory_and_enforces_foreign_keys(tmp_path: Path) -> None:
    conn = connect(tmp_path / "nested" / "test.db")
    try:
        assert (tmp_path / "nested" / "test.db").exists()
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    finally:
        conn.close()
