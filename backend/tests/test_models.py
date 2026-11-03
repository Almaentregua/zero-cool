"""Tests for models, severity mapping and database helpers."""

from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from zero_cool_api.db import create_db_engine, get_database_path, init_db
from zero_cool_api.models import Reference, Vulnerability, severity_from_cvss


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (None, None),
        (0.0, None),
        (0.1, "LOW"),
        (3.9, "LOW"),
        (4.0, "MEDIUM"),
        (6.9, "MEDIUM"),
        (7.0, "HIGH"),
        (8.9, "HIGH"),
        (9.0, "CRITICAL"),
        (10.0, "CRITICAL"),
        (10.1, None),
    ],
)
def test_severity_from_cvss(score: float | None, expected: str | None) -> None:
    assert severity_from_cvss(score) == expected


def test_database_path_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DATABASE_PATH", raising=False)
    assert get_database_path() == Path("data/zero_cool.db")


def test_database_path_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_PATH", "/somewhere/x.db")
    assert get_database_path() == Path("/somewhere/x.db")


def test_missing_data_is_stored_as_null(tmp_path: Path) -> None:
    engine = create_db_engine(tmp_path / "nested" / "t.db")
    init_db(engine)
    with Session(engine) as session:
        session.add(Vulnerability(cve_id="CVE-2024-0001", is_kev=True))
        session.commit()
        vuln = session.get(Vulnerability, "CVE-2024-0001")
        assert vuln is not None
        assert vuln.cvss_score is None
        assert vuln.epss_score is None
        assert vuln.ransomware_use is None


def test_foreign_keys_are_enforced(tmp_path: Path) -> None:
    engine = create_db_engine(tmp_path / "t.db")
    init_db(engine)
    with engine.connect() as conn:
        assert conn.execute(text("PRAGMA foreign_keys")).scalar() == 1
    with Session(engine) as session:
        session.add(Reference(cve_id="CVE-0000-0000", url="https://example.test"))
        with pytest.raises(IntegrityError):
            session.commit()
