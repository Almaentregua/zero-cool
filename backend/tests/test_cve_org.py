"""Tests for CVE.org / Vulnrichment parsing and sources (real records as fixtures, mocked HTTP)."""

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from zero_cool_api.http import FetchError
from zero_cool_api.research.adapters.cve_org import CveOrgSource, VulnrichmentSource
from zero_cool_api.sources.cve_org import CveOrgClient, parse_record

FIXTURES = Path(__file__).parent / "fixtures"


def load(name: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((FIXTURES / name).read_text())
    return data


def test_parse_log4j_cna_and_cisa_are_separate() -> None:
    record = parse_record(load("cve_org_log4j.json"))
    cna = record.cna
    assert cna.state == "PUBLISHED"
    assert cna.assigner == "apache"
    assert cna.published_at == "2021-12-10T00:00:00.000Z"
    assert cna.description is not None and cna.description.startswith("Apache Log4j2")
    assert [c.id for c in cna.cwes] == ["CWE-502", "CWE-400", "CWE-20"]
    assert cna.cvss == []  # the CNA gave no CVSS; CISA's must not leak in here
    assert cna.affected[0].vendor == "Apache Software Foundation"
    assert record.cisa is not None
    assert record.cisa.cvss[0].version == "3.1"
    assert record.cisa.cvss[0].score == 10.0
    assert record.cisa.cvss[0].severity == "CRITICAL"
    assert record.cisa.ssvc is not None
    assert record.cisa.ssvc.exploitation == "active"
    assert record.cisa.ssvc.automatable == "yes"
    assert record.cisa.ssvc.technical_impact == "total"


def test_parse_takes_cwe_from_cisa_when_cna_has_none_listed_there() -> None:
    record = parse_record(load("cve_org_webp.json"))
    assert record.cisa is not None
    assert [c.id for c in record.cisa.cwes] == ["CWE-787"]


def test_record_without_cisa_container() -> None:
    payload = load("cve_org_log4j.json")
    payload["containers"]["adp"] = [
        a for a in payload["containers"]["adp"] if a["providerMetadata"]["shortName"] != "CISA-ADP"
    ]
    assert parse_record(payload).cisa is None


def test_rejected_record_uses_the_reason_as_text() -> None:
    payload = {
        "cveMetadata": {"state": "REJECTED", "cveId": "CVE-2020-0001"},
        "containers": {
            "cna": {"rejectedReasons": [{"lang": "en", "value": "Duplicate of CVE-2020-0002"}]}
        },
    }
    record = parse_record(payload)
    assert record.cna.state == "REJECTED"
    assert record.cna.description == "Duplicate of CVE-2020-0002"
    assert record.cisa is None


def test_malformed_pieces_are_ignored_not_trusted() -> None:
    payload = {
        "cveMetadata": {"state": "PUBLISHED"},
        "containers": {
            "cna": {
                "descriptions": [{"lang": "en", "value": "ok\x00text"}],
                "problemTypes": [{"descriptions": [{"cweId": "<script>"}]}],
                "metrics": [{"cvssV3_1": {"baseScore": 99}}, "junk"],
                "references": [{"url": "javascript:alert(1)"}, {"url": "https://x.example/a"}],
            }
        },
    }
    cna = parse_record(payload).cna
    assert cna.description == "oktext"
    assert cna.cwes == []
    assert cna.cvss == []
    assert cna.references == ["https://x.example/a"]


@pytest.mark.parametrize("payload", [None, [], {}, {"cveMetadata": {}, "containers": []}])
def test_unexpected_payload_raises(payload: Any) -> None:
    with pytest.raises(FetchError):
        parse_record(payload)


def make_client(handler: Any) -> tuple[CveOrgClient, list[str]]:
    calls: list[str] = []

    def wrapped(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return handler(request)  # type: ignore[no-any-return]

    http = httpx.Client(transport=httpx.MockTransport(wrapped))
    return CveOrgClient(http), calls


def test_both_sources_share_one_request() -> None:
    client, calls = make_client(lambda _r: httpx.Response(200, json=load("cve_org_log4j.json")))
    cve = CveOrgSource(client).fetch("CVE-2021-44228")
    cisa = VulnrichmentSource(client).fetch("CVE-2021-44228")
    assert len(calls) == 1
    assert cve.data is not None and "ssvc" not in cve.data
    assert cisa.data is not None and cisa.data["ssvc"]["exploitation"] == "active"
    assert cve.origin_url == "https://www.cve.org/CVERecord?id=CVE-2021-44228"
    assert cisa.origin_url == "https://cveawg.mitre.org/api/cve/CVE-2021-44228"


def test_unknown_cve_is_no_data_for_both() -> None:
    client, _ = make_client(lambda _r: httpx.Response(404, json={"error": "CVE_RECORD_DNE"}))
    assert CveOrgSource(client).fetch("CVE-2099-99999").data is None
    assert VulnrichmentSource(client).fetch("CVE-2099-99999").data is None


def test_not_enriched_by_cisa_is_no_data_with_a_reason() -> None:
    payload = load("cve_org_log4j.json")
    payload["containers"]["adp"] = []
    client, _ = make_client(lambda _r: httpx.Response(200, json=payload))
    fetched = VulnrichmentSource(client).fetch("CVE-2021-44228")
    assert fetched.data is None
    assert fetched.message is not None and "not enriched" in fetched.message


def test_server_error_propagates() -> None:
    http = httpx.Client(transport=httpx.MockTransport(lambda _r: httpx.Response(400)))
    with pytest.raises(FetchError):
        CveOrgSource(CveOrgClient(http)).fetch("CVE-2021-44228")
