"""Tests for the NVD source and enrichment (mocked, no real network)."""

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy.orm import Session

from zero_cool_api.db import create_db_engine, init_db
from zero_cool_api.http import FetchError
from zero_cool_api.ingest.nvd import NvdAuthError, enrich_from_nvd
from zero_cool_api.models import Vulnerability
from zero_cool_api.sources.nvd import NvdClient, parse_cve

FIXTURE = Path(__file__).parent / "fixtures" / "nvd_log4j.json"
NOW = datetime(2026, 11, 2, 12, 0, 0)


def log4j_payload() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(FIXTURE.read_text())
    return data


def make_client(handler: Any, api_key: str | None = "secret-key") -> tuple[NvdClient, list[float]]:
    waits: list[float] = []
    clock = {"t": 0.0}
    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    client = NvdClient(http_client, api_key, sleep=waits.append, clock=lambda: clock["t"])
    return client, waits


def test_parse_cve_picks_newest_primary_cvss_and_english_text() -> None:
    data = parse_cve(log4j_payload()["vulnerabilities"][0]["cve"])
    assert data.cve_id == "CVE-2021-44228"
    assert data.description is not None
    assert data.description.startswith("Apache Log4j2")
    assert data.cvss_score == 10.0
    assert data.cvss_vector is not None
    assert data.cvss_vector.startswith("CVSS:3.1/AV:N")
    assert data.severity == "CRITICAL"
    assert data.published_at == datetime(2021, 12, 10, 10, 15, 9, 143000)


def test_parse_cve_drops_unsafe_and_invalid_references() -> None:
    data = parse_cve(log4j_payload()["vulnerabilities"][0]["cve"])
    assert data.references == [
        "https://logging.apache.org/log4j/2.x/security.html",
        "https://logging.apache.org/log4j/2.x/security.html",
    ]


def test_parse_cve_without_metrics_has_no_score() -> None:
    data = parse_cve({"id": "CVE-2024-0001", "descriptions": [], "metrics": {}})
    assert data.cvss_score is None
    assert data.severity is None
    assert data.description is None


def test_client_sends_key_as_header_and_throttles() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=log4j_payload())

    client, waits = make_client(handler)
    assert client.fetch("CVE-2021-44228") is not None
    assert client.fetch("CVE-2021-44228") is not None
    assert seen[0].headers["apiKey"] == "secret-key"
    assert seen[0].url.params["cveId"] == "CVE-2021-44228"
    assert waits == [0.65]  # the clock did not advance, so the full interval is awaited


def test_client_without_key_is_slower_and_sends_no_header() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"vulnerabilities": []})

    client, waits = make_client(handler, api_key=None)
    assert client.fetch("CVE-2021-44228") is None
    client.fetch("CVE-2021-44228")
    assert "apikey" not in seen[0].headers
    assert waits == [6.5]


def test_client_rejects_unexpected_payload() -> None:
    client, _ = make_client(lambda r: httpx.Response(200, json={"oops": 1}))
    with pytest.raises(FetchError):
        client.fetch("CVE-2021-44228")


def seeded_session(tmp_path: Path) -> Session:
    engine = create_db_engine(tmp_path / "t.db")
    init_db(engine)
    session = Session(engine)
    session.add_all(
        [
            Vulnerability(cve_id="CVE-2021-44228", is_kev=True, description="KEV text"),
            Vulnerability(cve_id="CVE-2020-0001", is_kev=True),
            Vulnerability(cve_id="CVE-2019-9999", is_kev=False),
        ]
    )
    session.commit()
    return session


def test_enrich_updates_kev_rows_only_and_marks_missing(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.params["cveId"] == "CVE-2021-44228":
            return httpx.Response(200, json=log4j_payload())
        return httpx.Response(200, json={"vulnerabilities": []})

    session = seeded_session(tmp_path)
    client, _ = make_client(handler)
    result = enrich_from_nvd(session, client, now=lambda: NOW)
    assert (result.enriched, result.not_found, result.failed) == (1, 1, 0)

    log4j = session.get(Vulnerability, "CVE-2021-44228")
    assert log4j is not None
    assert log4j.cvss_score == 10.0
    assert log4j.severity == "CRITICAL"
    assert log4j.description is not None
    assert log4j.description.startswith("Apache Log4j2")  # NVD replaces KEV text
    assert len(log4j.references) == 1  # duplicates removed
    missing = session.get(Vulnerability, "CVE-2020-0001")
    assert missing is not None
    assert missing.cvss_score is None  # never invented
    assert missing.nvd_fetched_at == NOW
    not_kev = session.get(Vulnerability, "CVE-2019-9999")
    assert not_kev is not None
    assert not_kev.nvd_fetched_at is None


def test_recently_fetched_are_skipped_unless_forced(tmp_path: Path) -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.params["cveId"])
        return httpx.Response(200, json={"vulnerabilities": []})

    session = seeded_session(tmp_path)
    client, _ = make_client(handler)
    enrich_from_nvd(session, client, now=lambda: NOW)
    calls.clear()

    again = enrich_from_nvd(session, client, now=lambda: NOW + timedelta(days=1))
    assert calls == []
    assert again.skipped_recent == 2

    forced = enrich_from_nvd(session, client, force=True, now=lambda: NOW)
    assert len(calls) == 2
    assert forced.skipped_recent == 0

    stale = enrich_from_nvd(session, client, now=lambda: NOW + timedelta(days=8))
    assert stale.skipped_recent == 0


def test_limit_and_failures_do_not_stop_the_run(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    session = seeded_session(tmp_path)
    client, _ = make_client(handler)
    result = enrich_from_nvd(session, client, limit=1, now=lambda: NOW)
    assert result.failed == 1

    result = enrich_from_nvd(session, client, now=lambda: NOW)
    assert result.failed == 2  # failed CVEs are not marked as fetched, so they are retried


def test_rejected_key_aborts_with_clear_error(tmp_path: Path) -> None:
    session = seeded_session(tmp_path)
    client, _ = make_client(lambda r: httpx.Response(403))
    with pytest.raises(NvdAuthError) as info:
        enrich_from_nvd(session, client, now=lambda: NOW)
    assert "secret-key" not in str(info.value)
