"""Tests for the advisory tables."""

from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from zero_cool_api.db import create_db_engine, init_db
from zero_cool_api.models import (
    Advisory,
    AdvisoryCve,
    AdvisoryPackage,
    AdvisoryReference,
)


def make_session(tmp_path: Path) -> Session:
    engine = create_db_engine(tmp_path / "t.db")
    init_db(engine)
    return Session(engine)


def test_advisory_without_cve_and_missing_fields_is_valid(tmp_path: Path) -> None:
    session = make_session(tmp_path)
    session.add(Advisory(id="GHSA-aaaa-bbbb-cccc"))
    session.commit()
    advisory = session.get(Advisory, "GHSA-aaaa-bbbb-cccc")
    assert advisory is not None
    assert advisory.cves == []
    assert advisory.severity is None
    assert advisory.epss_score is None
    assert advisory.github_reviewed is None


def test_children_are_stored_and_deleted_with_the_advisory(tmp_path: Path) -> None:
    session = make_session(tmp_path)
    session.add(
        Advisory(
            id="GHSA-aaaa-bbbb-cccc",
            cves=[AdvisoryCve(cve_id="CVE-2021-44228")],
            packages=[AdvisoryPackage(ecosystem="Maven", name="org.x:y", fixed_versions="2.15.0")],
            references=[AdvisoryReference(url="https://example.test")],
        )
    )
    session.commit()
    session.delete(session.get(Advisory, "GHSA-aaaa-bbbb-cccc"))
    session.commit()
    for model in (AdvisoryCve, AdvisoryPackage, AdvisoryReference):
        assert session.scalars(select(model)).all() == []


def test_child_rows_need_an_existing_advisory(tmp_path: Path) -> None:
    session = make_session(tmp_path)
    session.add(AdvisoryCve(advisory_id="GHSA-missing", cve_id="CVE-2021-44228"))
    with pytest.raises(IntegrityError):
        session.commit()


def test_new_tables_do_not_disturb_an_existing_database(tmp_path: Path) -> None:
    """init_db only adds missing tables, so earlier data survives an upgrade."""
    from zero_cool_api.models import Vulnerability

    engine = create_db_engine(tmp_path / "t.db")
    Vulnerability.__table__.create(engine)  # type: ignore[attr-defined]
    with Session(engine) as session:
        session.add(Vulnerability(cve_id="CVE-2020-0001", is_kev=True))
        session.commit()
    init_db(engine)
    with Session(engine) as session:
        assert session.get(Vulnerability, "CVE-2020-0001") is not None
        assert session.get(Advisory, "x") is None
