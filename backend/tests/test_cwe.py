"""Tests for the MITRE CWE client and research source (real fixtures, mocked HTTP)."""

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from zero_cool_api.http import FetchError
from zero_cool_api.research.adapters.cwe import CweSource
from zero_cool_api.sources.cve_org import CveOrgClient
from zero_cool_api.sources.cwe import CweClient, parse_category, parse_weakness

FIXTURES = Path(__file__).parent / "fixtures"


def load(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text())


def test_parse_weakness() -> None:
    entry = parse_weakness(load("cwe_weakness_502.json"))
    assert entry.id == "CWE-502"
    assert entry.kind == "weakness"
    assert entry.name == "Deserialization of Untrusted Data"
    assert entry.abstraction == "Base"
    assert entry.description is not None and entry.description.startswith(
        "The product deserializes"
    )
    assert entry.likelihood_of_exploit == "Medium"
    assert entry.consequences[0]["scope"] == ["Integrity"]


def test_parse_category() -> None:
    entry = parse_category(load("cwe_category_16.json"))
    assert (entry.id, entry.kind, entry.name) == ("CWE-16", "category", "Configuration")
    assert entry.description is not None and "configuration" in entry.description


@pytest.mark.parametrize("payload", [None, {}, {"Weaknesses": []}, {"Weaknesses": ["x"]}])
def test_unexpected_weakness_payload_raises(payload: Any) -> None:
    with pytest.raises(FetchError):
        parse_weakness(payload)


def cwe_handler(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if path.endswith("/cwe/502"):
        return httpx.Response(200, json=[{"Type": "base_weakness", "ID": "502"}])
    if path.endswith("/weakness/502"):
        return httpx.Response(200, json=load("cwe_weakness_502.json"))
    if path.endswith("/cwe/16"):
        return httpx.Response(200, json=[{"Type": "category", "ID": "16"}])
    if path.endswith("/category/16"):
        return httpx.Response(200, json=load("cwe_category_16.json"))
    if path.endswith("/cwe/1000"):
        return httpx.Response(200, json=[{"Type": "view", "ID": "1000"}])
    return httpx.Response(404, json="at least one CWE not found")


def make_cwe_client() -> tuple[CweClient, list[str]]:
    calls: list[str] = []

    def wrapped(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return cwe_handler(request)

    return CweClient(httpx.Client(transport=httpx.MockTransport(wrapped))), calls


def test_client_dispatches_by_type_and_memoizes() -> None:
    client, calls = make_cwe_client()
    weakness = client.fetch("CWE-502")
    category = client.fetch("CWE-16")
    assert weakness is not None and weakness.kind == "weakness"
    assert category is not None and category.kind == "category"
    before = len(calls)
    client.fetch("CWE-502")
    assert len(calls) == before


def test_client_views_and_unknown_ids_are_none() -> None:
    client, _ = make_cwe_client()
    assert client.fetch("CWE-1000") is None
    assert client.fetch("CWE-99999") is None


def test_client_server_error_propagates() -> None:
    http = httpx.Client(transport=httpx.MockTransport(lambda _r: httpx.Response(400)))
    with pytest.raises(FetchError):
        CweClient(http).fetch("CWE-502")


def make_source(record_payload: Any, status: int = 200) -> CweSource:
    records = CveOrgClient(
        httpx.Client(
            transport=httpx.MockTransport(lambda _r: httpx.Response(status, json=record_payload))
        )
    )
    cwes, _ = make_cwe_client()
    return CweSource(records, cwes)


def test_source_says_who_listed_each_cwe() -> None:
    payload = load("cve_org_log4j.json")
    fetched = make_source(payload).fetch("CVE-2021-44228")
    assert fetched.data is not None
    by_id = {c["id"]: c for c in fetched.data["cwes"]}
    assert set(by_id) == {"CWE-502", "CWE-400", "CWE-20"}
    assert by_id["CWE-502"]["listed_by"] == ["cna"]
    assert by_id["CWE-502"]["name"] == "Deserialization of Untrusted Data"
    assert by_id["CWE-502"]["url"] == "https://cwe.mitre.org/data/definitions/502.html"
    # CWE-400 and CWE-20 are not in the mocked catalog: shown, but without invented text.
    assert by_id["CWE-400"]["name"] is None
    assert "description" not in by_id["CWE-400"]


def test_source_merges_cna_and_cisa_listing_of_the_same_cwe() -> None:
    payload = load("cve_org_log4j.json")
    cisa = next(
        a for a in payload["containers"]["adp"] if a["providerMetadata"]["shortName"] == "CISA-ADP"
    )
    cisa["problemTypes"] = [{"descriptions": [{"cweId": "CWE-502", "description": "x"}]}]
    fetched = make_source(payload).fetch("CVE-2021-44228")
    assert fetched.data is not None
    by_id = {c["id"]: c for c in fetched.data["cwes"]}
    assert by_id["CWE-502"]["listed_by"] == ["cna", "cisa"]


def test_source_no_cwe_and_unknown_cve_are_no_data() -> None:
    payload = load("cve_org_log4j.json")
    payload["containers"]["cna"]["problemTypes"] = []
    payload["containers"]["adp"] = []
    none_listed = make_source(payload).fetch("CVE-2021-44228")
    assert none_listed.data is None and "no CWE" in (none_listed.message or "")
    unknown = make_source({"error": "CVE_RECORD_DNE"}, status=404).fetch("CVE-2099-99999")
    assert unknown.data is None
