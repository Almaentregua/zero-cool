"""Tests for the OSV source and advisory ingestion (fixtures only, no real network)."""

import json
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy.orm import Session

from zero_cool_api.db import create_db_engine, init_db
from zero_cool_api.ingest.osv import upsert_advisories
from zero_cool_api.models import Advisory
from zero_cool_api.sources.osv import (
    download_dump,
    iter_advisories,
    iter_zip_records,
    parse_record,
)

GHSA = "GHSA-jfh8-c2jp-5v3q"
WANTED = {"Maven", "npm"}


def record(**changes: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": GHSA,
        "summary": "Log4j RCE",
        "details": "# Heading\n<script>alert(1)</script>",
        "aliases": ["CVE-2021-44228", "not-a-cve"],
        "modified": "2025-10-22T19:37:02.616807Z",
        "published": "2021-12-10T00:40:41Z",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
        "database_specific": {"severity": "CRITICAL", "github_reviewed": True},
        "references": [
            {"url": "https://example.test/a"},
            {"url": "javascript:alert(1)"},
            {"url": "https://example.test/a"},
            {"type": "WEB"},
        ],
        "affected": [
            {
                "package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "2.13.0"}, {"fixed": "2.15.0"}]}
                ],
            },
            {
                "package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.3.1"}]}
                ],
            },
            {"package": {"ecosystem": "PyPI", "name": "other"}, "ranges": []},
        ],
    }
    base.update(changes)
    return base


def test_parse_record_normalizes_fields() -> None:
    adv = parse_record(record(), WANTED)
    assert adv is not None
    assert adv.id == GHSA
    assert adv.severity == "CRITICAL"
    assert adv.cvss_vector is not None
    assert adv.cvss_vector.startswith("CVSS:3.1/")
    assert adv.github_reviewed is True
    assert adv.cve_ids == ["CVE-2021-44228"]
    assert adv.references == ["https://example.test/a"]  # unsafe and duplicate links dropped
    assert adv.published_at == datetime(2021, 12, 10, 0, 40, 41)  # naive UTC
    assert adv.details is not None
    assert "<script>" in adv.details  # kept as text; rendering is the frontend's job


def test_packages_are_merged_filtered_and_fixed_versions_extracted() -> None:
    adv = parse_record(record(), WANTED)
    assert adv is not None
    assert [(p.ecosystem, p.name) for p in adv.packages] == [
        ("Maven", "org.apache.logging.log4j:log4j-core")
    ]  # PyPI dropped, duplicate package merged
    assert adv.packages[0].fixed_versions == "2.15.0, 2.3.1"
    assert adv.packages[0].ranges_json is not None
    assert len(json.loads(adv.packages[0].ranges_json)) == 2


def test_moderate_becomes_medium_and_unknown_severity_is_none() -> None:
    adv = parse_record(record(database_specific={"severity": "MODERATE"}), WANTED)
    assert adv is not None
    assert adv.severity == "MEDIUM"
    assert adv.github_reviewed is None
    adv = parse_record(record(database_specific={"severity": "weird"}), WANTED)
    assert adv is not None
    assert adv.severity is None


def test_missing_optional_data_is_none() -> None:
    adv = parse_record(
        {"id": GHSA, "affected": [{"package": {"ecosystem": "npm", "name": "x"}}]}, WANTED
    )
    assert adv is not None
    assert (adv.summary, adv.cvss_vector, adv.published_at, adv.severity) == (
        None,
        None,
        None,
        None,
    )
    assert adv.cve_ids == []
    assert adv.packages[0].ranges_json is None


def test_vector_without_cvss_prefix_is_ignored() -> None:
    adv = parse_record(record(severity=[{"type": "CVSS_V3", "score": "9.8"}]), WANTED)
    assert adv is not None
    assert adv.cvss_vector is None


def test_withdrawn_is_flagged_and_other_ecosystems_are_skipped() -> None:
    adv = parse_record(record(withdrawn="2024-01-01T00:00:00Z"), WANTED)
    assert adv is not None
    assert adv.withdrawn is True
    assert parse_record(record(), {"Go"}) is None


def test_invalid_id_is_rejected() -> None:
    with pytest.raises(ValueError):
        parse_record(record(id="MAL-2024-1"), WANTED)


def make_zip(path: Path, members: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return path


def test_zip_reader_keeps_only_safe_ghsa_members(tmp_path: Path) -> None:
    good = json.dumps(record()).encode()
    archive = make_zip(
        tmp_path / "all.zip",
        {
            f"{GHSA}.json": good,
            "MAL-2024-1.json": good,  # malware reports are not imported
            "../GHSA-evil-evil-evil.json": good,
            "dir/GHSA-aaaa-aaaa-aaaa.json": good,
            "GHSA-bbbb-bbbb-bbbb.json": b"{not json",
            "GHSA-cccc-cccc-cccc.json": b"[1, 2]",
            "GHSA-dddd-dddd-dddd.json": b"x" * 5_000_001,
            "GHSA-eeee-eeee-eeee.txt": good,
        },
    )
    assert [r["id"] for r in iter_zip_records(archive)] == [GHSA]


def test_iter_advisories_survives_an_invalid_record_in_the_middle(tmp_path: Path) -> None:
    other = record(id="GHSA-aaaa-bbbb-cccc")
    bad = record(id="GHSA-bbbb-cccc-dddd", modified="not a date")
    archive = make_zip(
        tmp_path / "all.zip",
        {
            "GHSA-1.json": json.dumps(record()).encode(),
            "GHSA-2.json": json.dumps(bad).encode(),
            "GHSA-3.json": json.dumps(other).encode(),
        },
    )
    assert [a.id for a in iter_advisories(archive, WANTED)] == [GHSA, "GHSA-aaaa-bbbb-cccc"]


def test_download_dump_rejects_unsafe_ecosystem_names(tmp_path: Path) -> None:
    client = httpx.Client(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, content=b"x"))
    )
    with pytest.raises(ValueError):
        download_dump(client, "../etc/passwd", tmp_path)


def test_download_dump_uses_the_cache_directory(tmp_path: Path) -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, content=b"zip")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    path, changed = download_dump(
        client, "Maven", tmp_path / "cache", url_template="https://osv.test/{ecosystem}/all.zip"
    )
    assert changed is True
    assert path == tmp_path / "cache" / "osv-Maven.zip"
    assert seen == ["https://osv.test/Maven/all.zip"]


def session(tmp_path: Path) -> Session:
    engine = create_db_engine(tmp_path / "t.db")
    init_db(engine)
    return Session(engine)


def parsed(**changes: Any) -> Any:
    adv = parse_record(record(**changes), WANTED)
    assert adv is not None
    return adv


def test_upsert_creates_children(tmp_path: Path) -> None:
    db = session(tmp_path)
    result = upsert_advisories(db, [parsed()])
    assert (result.created, result.updated, result.unchanged, result.removed) == (1, 0, 0, 0)
    advisory = db.get(Advisory, GHSA)
    assert advisory is not None
    assert [c.cve_id for c in advisory.cves] == ["CVE-2021-44228"]
    assert [p.name for p in advisory.packages] == ["org.apache.logging.log4j:log4j-core"]
    assert [r.url for r in advisory.references] == ["https://example.test/a"]


def test_same_record_twice_is_unchanged_and_modified_record_is_rewritten(tmp_path: Path) -> None:
    db = session(tmp_path)
    upsert_advisories(db, [parsed()])
    assert upsert_advisories(db, [parsed(), parsed()]).unchanged == 2

    newer = parsed(modified="2026-01-01T00:00:00Z", summary="Updated", aliases=[])
    result = upsert_advisories(db, [newer])
    assert result.updated == 1
    advisory = db.get(Advisory, GHSA)
    assert advisory is not None
    assert advisory.summary == "Updated"
    assert advisory.cves == []  # children were replaced, not accumulated
    assert len(advisory.packages) == 1


def test_update_preserves_epss(tmp_path: Path) -> None:
    db = session(tmp_path)
    upsert_advisories(db, [parsed()])
    advisory = db.get(Advisory, GHSA)
    assert advisory is not None
    advisory.epss_score = 0.9
    db.commit()
    upsert_advisories(db, [parsed(modified="2026-01-01T00:00:00Z")])
    db.expire_all()
    advisory = db.get(Advisory, GHSA)
    assert advisory is not None
    assert advisory.epss_score == 0.9


def test_withdrawn_advisories_are_removed_and_never_created(tmp_path: Path) -> None:
    db = session(tmp_path)
    upsert_advisories(db, [parsed()])
    result = upsert_advisories(db, [parsed(withdrawn="2026-01-01T00:00:00Z")])
    assert result.removed == 1
    assert db.get(Advisory, GHSA) is None
    again = upsert_advisories(db, [parsed(withdrawn="2026-01-01T00:00:00Z")])
    assert (again.created, again.removed) == (0, 0)
