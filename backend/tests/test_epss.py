"""Tests for the EPSS source and ingestion (mocked, no real network)."""

from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy.orm import Session

from zero_cool_api.db import create_db_engine, init_db
from zero_cool_api.http import FetchError
from zero_cool_api.ingest.epss import apply_epss, kev_cve_ids
from zero_cool_api.models import Vulnerability
from zero_cool_api.sources.epss import BATCH_SIZE, fetch_epss, parse_rows


def row(cve: str, epss: str = "0.5", percentile: str = "0.9") -> dict[str, str]:
    return {"cve": cve, "epss": epss, "percentile": percentile, "date": "2026-11-02"}


def test_parse_rows_converts_text_to_numbers() -> None:
    scores = parse_rows({"data": [row("CVE-2021-44228", "0.999990000", "1.000000000")]})
    assert scores[0].cve_id == "CVE-2021-44228"
    assert scores[0].score == pytest.approx(0.99999)
    assert scores[0].percentile == 1.0


def test_parse_rows_skips_malformed_rows() -> None:
    payload = {
        "data": [
            row("CVE-2020-0001"),
            row("not-a-cve"),
            row("CVE-2020-0002", epss="abc"),
            row("CVE-2020-0003", epss="1.5"),  # out of range
            {"cve": "CVE-2020-0004"},  # missing fields
        ]
    }
    assert [s.cve_id for s in parse_rows(payload)] == ["CVE-2020-0001"]


def test_parse_rows_rejects_unexpected_payload() -> None:
    with pytest.raises(FetchError):
        parse_rows({"status": "OK"})


def test_fetch_epss_batches_requests_and_ignores_unrequested_ids() -> None:
    requested: list[list[str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        ids = request.url.params["cve"].split(",")
        requested.append(ids)
        data = [row(i) for i in ids if i != "CVE-2020-0000"]  # one unknown to EPSS
        data.append(row("CVE-1999-9999"))  # never asked for
        return httpx.Response(200, json={"data": data})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    ids = [f"CVE-2020-{n:04d}" for n in range(BATCH_SIZE + 5)] + ["bad-id", "CVE-2020-0001"]
    progress: list[tuple[int, int]] = []
    result = fetch_epss(client, ids, progress=lambda d, t: progress.append((d, t)))

    assert [len(r) for r in requested] == [BATCH_SIZE, 5]  # deduplicated, invalid id dropped
    assert "CVE-2020-0000" not in result
    assert "CVE-1999-9999" not in result
    assert len(result) == BATCH_SIZE + 5 - 1
    assert progress == [(BATCH_SIZE, BATCH_SIZE + 5), (BATCH_SIZE + 5, BATCH_SIZE + 5)]


def test_fetch_epss_propagates_failures() -> None:
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(404)))
    with pytest.raises(FetchError):
        fetch_epss(client, ["CVE-2020-0001"])


def test_apply_epss_updates_only_kev_rows(tmp_path: Path) -> None:
    engine = create_db_engine(tmp_path / "t.db")
    init_db(engine)
    with Session(engine) as session:
        session.add_all(
            [
                Vulnerability(cve_id="CVE-2020-0001", is_kev=True),
                Vulnerability(cve_id="CVE-2020-0002", is_kev=True, epss_score=0.1),
                Vulnerability(cve_id="CVE-2020-0003", is_kev=False),
            ]
        )
        session.commit()
        assert kev_cve_ids(session) == ["CVE-2020-0001", "CVE-2020-0002"]

        scores: dict[str, Any] = {
            s.cve_id: s
            for s in parse_rows(
                {"data": [row("CVE-2020-0001", "0.25", "0.8"), row("CVE-2020-0003")]}
            )
        }
        assert apply_epss(session, scores) == (1, 1)

        first = session.get(Vulnerability, "CVE-2020-0001")
        assert first is not None
        assert (first.epss_score, first.epss_percentile) == (0.25, 0.8)
        unknown = session.get(Vulnerability, "CVE-2020-0002")
        assert unknown is not None
        assert unknown.epss_score == 0.1  # EPSS did not know it: previous value kept
        not_kev = session.get(Vulnerability, "CVE-2020-0003")
        assert not_kev is not None
        assert not_kev.epss_score is None


def test_all_cve_ids_joins_kev_and_advisory_cves(tmp_path: Path) -> None:
    from zero_cool_api.ingest.epss import all_cve_ids
    from zero_cool_api.models import Advisory, AdvisoryCve

    engine = create_db_engine(tmp_path / "t.db")
    init_db(engine)
    with Session(engine) as session:
        session.add(Vulnerability(cve_id="CVE-2020-0001", is_kev=True))
        session.add(Vulnerability(cve_id="CVE-2020-0009", is_kev=False))
        session.add(Advisory(id="GHSA-aaaa-bbbb-cccc", cves=[AdvisoryCve(cve_id="CVE-2020-0001")]))
        session.add(Advisory(id="GHSA-bbbb-cccc-dddd", cves=[AdvisoryCve(cve_id="CVE-2021-0002")]))
        session.commit()
        assert all_cve_ids(session) == ["CVE-2020-0001", "CVE-2021-0002"]


def test_advisory_epss_is_the_highest_among_its_cves(tmp_path: Path) -> None:
    from zero_cool_api.ingest.epss import apply_epss_to_advisories
    from zero_cool_api.models import Advisory, AdvisoryCve

    engine = create_db_engine(tmp_path / "t.db")
    init_db(engine)
    with Session(engine) as session:
        session.add_all(
            [
                Advisory(
                    id="GHSA-aaaa-bbbb-cccc",
                    cves=[AdvisoryCve(cve_id="CVE-2020-0001"), AdvisoryCve(cve_id="CVE-2020-0002")],
                ),
                Advisory(id="GHSA-bbbb-cccc-dddd", cves=[AdvisoryCve(cve_id="CVE-2020-0003")]),
                Advisory(id="GHSA-cccc-dddd-eeee"),  # no CVE at all
                Advisory(
                    id="GHSA-dddd-eeee-ffff",
                    epss_score=0.3,
                    cves=[AdvisoryCve(cve_id="CVE-2020-0004")],
                ),
            ]
        )
        session.commit()
        scores = {
            s.cve_id: s
            for s in parse_rows(
                {
                    "data": [
                        row("CVE-2020-0001", "0.2", "0.5"),
                        row("CVE-2020-0002", "0.8", "0.9"),
                        row("CVE-2020-0003", "0.0", "0.1"),
                    ]
                }
            )
        }
        assert apply_epss_to_advisories(session, scores) == (2, 1)

        def get(advisory_id: str) -> Advisory:
            found = session.get(Advisory, advisory_id)
            assert found is not None
            return found

        multi = get("GHSA-aaaa-bbbb-cccc")
        assert (multi.epss_score, multi.epss_percentile) == (0.8, 0.9)
        zero = get("GHSA-bbbb-cccc-dddd")
        assert zero.epss_score == 0.0  # a real zero is kept, not treated as missing
        assert get("GHSA-cccc-dddd-eeee").epss_score is None
        assert get("GHSA-dddd-eeee-ffff").epss_score == 0.3  # unscored: previous value kept
