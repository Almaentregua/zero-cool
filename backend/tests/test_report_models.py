"""Tests for the investigation report tables."""

from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from zero_cool_api.db import create_db_engine, init_db
from zero_cool_api.models import Report, ReportCve, ReportSourceResult

NOW = datetime(2026, 11, 4, tzinfo=UTC)


def make_session(tmp_path: Path) -> Session:
    engine = create_db_engine(tmp_path / "t.db")
    init_db(engine)
    return Session(engine)


def make_report(title: str = "Log4Shell") -> Report:
    return Report(title=title, created_at=NOW, updated_at=NOW)


def test_report_defaults(tmp_path: Path) -> None:
    session = make_session(tmp_path)
    session.add(make_report())
    session.commit()
    report = session.scalars(select(Report)).one()
    assert report.notes == ""
    assert report.status == "open"
    assert report.cves == []
    assert report.results == []


def test_children_are_deleted_with_the_report(tmp_path: Path) -> None:
    session = make_session(tmp_path)
    report = make_report()
    report.cves.append(ReportCve(cve_id="CVE-2021-44228"))
    report.results.append(
        ReportSourceResult(
            cve_id="CVE-2021-44228",
            source="nvd",
            status="ok",
            origin_url="https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
            retrieved_at=NOW,
            payload_json="{}",
        )
    )
    session.add(report)
    session.commit()
    session.delete(report)
    session.commit()
    assert session.scalars(select(ReportCve)).all() == []
    assert session.scalars(select(ReportSourceResult)).all() == []


def test_source_with_no_data_is_stored_without_payload(tmp_path: Path) -> None:
    session = make_session(tmp_path)
    report = make_report()
    report.results.append(
        ReportSourceResult(
            cve_id="CVE-2021-44228",
            source="exploit_db",
            status="no_data",
            message="No entry found",
            retrieved_at=NOW,
        )
    )
    session.add(report)
    session.commit()
    result = session.scalars(select(ReportSourceResult)).one()
    assert result.payload_json is None
    assert result.origin_url is None


def test_one_result_per_report_cve_and_source(tmp_path: Path) -> None:
    session = make_session(tmp_path)
    report = make_report()
    for _ in range(2):
        report.results.append(
            ReportSourceResult(cve_id="CVE-1", source="nvd", status="ok", retrieved_at=NOW)
        )
    session.add(report)
    with pytest.raises(IntegrityError):
        session.commit()


def test_same_cve_cannot_be_added_twice_to_a_report(tmp_path: Path) -> None:
    session = make_session(tmp_path)
    report = make_report()
    report.cves.extend([ReportCve(cve_id="CVE-1"), ReportCve(cve_id="CVE-1")])
    session.add(report)
    with pytest.raises(IntegrityError):
        session.commit()
