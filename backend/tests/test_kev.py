"""Tests for the KEV source and its ingestion (fixtures only, no real network)."""

import json
from datetime import date
from pathlib import Path

import httpx
import pytest
from sqlalchemy.orm import Session

from zero_cool_api.db import create_db_engine, init_db
from zero_cool_api.http import FetchError
from zero_cool_api.ingest.kev import upsert_kev
from zero_cool_api.models import Vulnerability
from zero_cool_api.sources.kev import clean_text, fetch_kev, parse_catalog

FIXTURE = Path(__file__).parent / "fixtures" / "kev_sample.json"


def payload() -> dict[str, object]:
    data: dict[str, object] = json.loads(FIXTURE.read_text())
    return data


def test_parse_catalog_normalizes_and_skips_invalid() -> None:
    entries = parse_catalog(payload())
    assert [e.cve_id for e in entries] == ["CVE-2021-44228", "CVE-2020-0001"]
    log4j = entries[0]
    assert log4j.vendor == "Apache"
    assert log4j.date_added == date(2021, 12, 10)
    assert log4j.ransomware_use is True
    assert entries[1].ransomware_use is False


def test_untrusted_text_is_sanitized_not_interpreted() -> None:
    second = parse_catalog(payload())[1]
    assert second.vendor == "Acme Corp"  # control character removed
    assert second.description == "<script>alert(1)</script> text"  # kept as text


def test_clean_text_edge_cases() -> None:
    assert clean_text(None) is None
    assert clean_text("   ") is None
    assert len(clean_text("a" * 10000) or "") == 5000


def test_unknown_ransomware_value_is_none() -> None:
    raw = {"cveID": "CVE-2020-1111", "dateAdded": "2020-01-01", "knownRansomwareCampaignUse": "?"}
    from zero_cool_api.sources.kev import parse_entry

    assert parse_entry(raw).ransomware_use is None


def test_unexpected_payload_raises() -> None:
    with pytest.raises(FetchError):
        parse_catalog({"nope": []})


def test_fetch_kev_uses_client() -> None:
    client = httpx.Client(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json=payload()))
    )
    assert len(fetch_kev(client, "https://kev.test")) == 2


def test_upsert_creates_then_updates_and_preserves_other_sources(tmp_path: Path) -> None:
    engine = create_db_engine(tmp_path / "t.db")
    init_db(engine)
    entries = parse_catalog(payload())
    with Session(engine) as session:
        assert upsert_kev(session, entries) == (2, 0)
        vuln = session.get(Vulnerability, "CVE-2021-44228")
        assert vuln is not None
        vuln.cvss_score = 10.0  # as if NVD had written it
        vuln.description = "NVD description"
        session.commit()

        assert upsert_kev(session, entries) == (0, 2)
        session.expire_all()
        vuln = session.get(Vulnerability, "CVE-2021-44228")
        assert vuln is not None
        assert vuln.cvss_score == 10.0
        assert vuln.description == "NVD description"
        assert vuln.is_kev is True
        assert vuln.ransomware_use is True
