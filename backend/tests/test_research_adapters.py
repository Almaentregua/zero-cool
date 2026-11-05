"""Tests for the research source adapters (local database and mocked HTTP only)."""

import json
from datetime import date
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy.orm import Session

from zero_cool_api.db import create_db_engine, init_db
from zero_cool_api.http import FetchError
from zero_cool_api.models import Advisory, AdvisoryCve, AdvisoryPackage, Vulnerability
from zero_cool_api.research.adapters.epss import EpssSource
from zero_cool_api.research.adapters.kev import KevSource
from zero_cool_api.research.adapters.nvd import NvdSource
from zero_cool_api.research.adapters.osv import OsvSource
from zero_cool_api.research.registry import build_sources
from zero_cool_api.research.runner import research
from zero_cool_api.sources.nvd import NvdClient

NVD_FIXTURE = Path(__file__).parent / "fixtures" / "nvd_log4j.json"
LOG4J = "CVE-2021-44228"


@pytest.fixture
def factory(tmp_path: Path) -> Any:
    engine = create_db_engine(tmp_path / "t.db")
    init_db(engine)
    return lambda: Session(engine)


def test_kev_source_reports_listed_cve(factory: Any) -> None:
    with factory() as s:
        s.add(
            Vulnerability(
                cve_id=LOG4J,
                is_kev=True,
                vendor="Apache",
                product="Log4j2",
                date_added=date(2021, 12, 10),
                ransomware_use=True,
            )
        )
        s.commit()
    fetched = KevSource(factory).fetch(LOG4J)
    assert fetched.data is not None
    assert fetched.data["in_kev"] is True
    assert fetched.data["date_added"] == "2021-12-10"
    assert fetched.data["ransomware_use"] is True
    assert fetched.origin_url is not None


def test_kev_source_not_listed_is_an_answer_not_missing_data(factory: Any) -> None:
    with factory() as s:
        s.add(Vulnerability(cve_id="CVE-2000-0001", is_kev=True))
        s.commit()
    fetched = KevSource(factory).fetch(LOG4J)
    assert fetched.data == {"in_kev": False}


def test_kev_source_fails_when_catalog_was_never_ingested(factory: Any) -> None:
    with pytest.raises(FetchError):
        KevSource(factory).fetch(LOG4J)


def nvd_source(handler: Any) -> NvdSource:
    http = httpx.Client(transport=httpx.MockTransport(handler))
    return NvdSource(NvdClient(http, "secret-key", sleep=lambda _s: None))


def test_nvd_source_returns_normalized_data() -> None:
    payload = json.loads(NVD_FIXTURE.read_text())
    fetched = nvd_source(lambda _r: httpx.Response(200, json=payload)).fetch(LOG4J)
    assert fetched.data is not None
    assert fetched.data["cvss_score"] == 10.0
    assert fetched.data["severity"] == "CRITICAL"
    assert "cve_id" not in fetched.data
    assert fetched.origin_url == f"https://nvd.nist.gov/vuln/detail/{LOG4J}"


def test_nvd_source_unknown_cve_is_no_data() -> None:
    fetched = nvd_source(lambda _r: httpx.Response(200, json={"vulnerabilities": []})).fetch(LOG4J)
    assert fetched.data is None
    assert fetched.message is not None


def epss_source(handler: Any) -> EpssSource:
    return EpssSource(httpx.Client(transport=httpx.MockTransport(handler)))


def test_epss_source_score_and_missing() -> None:
    ok = epss_source(
        lambda _r: httpx.Response(
            200, json={"data": [{"cve": LOG4J, "epss": "0.94", "percentile": "0.99"}]}
        )
    ).fetch(LOG4J)
    assert ok.data == {"score": 0.94, "percentile": 0.99}
    empty = epss_source(lambda _r: httpx.Response(200, json={"data": []})).fetch(LOG4J)
    assert empty.data is None


def test_osv_source_lists_advisories_with_packages(factory: Any) -> None:
    with factory() as s:
        advisory = Advisory(id="GHSA-jfh8-c2jp-5v3q", summary="Log4Shell", severity="CRITICAL")
        advisory.cves.append(AdvisoryCve(cve_id=LOG4J))
        advisory.packages.append(
            AdvisoryPackage(
                ecosystem="Maven",
                name="org.apache.logging.log4j:log4j-core",
                fixed_versions="2.15.0",
            )
        )
        s.add(advisory)
        s.add(Advisory(id="GHSA-other"))
        s.commit()
    fetched = OsvSource(factory).fetch(LOG4J)
    assert fetched.data is not None
    items = fetched.data["advisories"]
    assert [i["id"] for i in items] == ["GHSA-jfh8-c2jp-5v3q"]
    assert items[0]["packages"][0]["fixed_versions"] == "2.15.0"
    assert items[0]["url"] == "https://osv.dev/vulnerability/GHSA-jfh8-c2jp-5v3q"


def test_osv_source_no_advisory_and_not_ingested(factory: Any) -> None:
    with pytest.raises(FetchError):
        OsvSource(factory).fetch(LOG4J)
    with factory() as s:
        s.add(Advisory(id="GHSA-other"))
        s.commit()
    fetched = OsvSource(factory).fetch(LOG4J)
    assert fetched.data is None
    assert fetched.message is not None and "Maven or npm" in fetched.message


def test_registry_and_end_to_end_run_with_mocks(factory: Any) -> None:
    payload = json.loads(NVD_FIXTURE.read_text())
    cve_org_payload = json.loads((NVD_FIXTURE.parent / "cve_org_log4j.json").read_text())

    cwe_payload = json.loads((NVD_FIXTURE.parent / "cwe_weakness_502.json").read_text())

    def handler(request: httpx.Request) -> httpx.Response:
        if "nvd.nist.gov" in request.url.host:
            return httpx.Response(200, json=payload)
        if "cwe-api.mitre.org" in request.url.host:
            if "/weakness/" in request.url.path:
                return httpx.Response(200, json=cwe_payload)
            return httpx.Response(200, json=[{"Type": "base_weakness", "ID": "502"}])
        if "cveawg.mitre.org" in request.url.host:
            return httpx.Response(200, json=cve_org_payload)
        return httpx.Response(
            200, json={"data": [{"cve": LOG4J, "epss": "0.9", "percentile": "0.98"}]}
        )

    with factory() as s:
        s.add(Vulnerability(cve_id=LOG4J, is_kev=True))
        s.add(Advisory(id="GHSA-x"))
        s.commit()
    client = httpx.Client(transport=httpx.MockTransport(handler))
    sources = build_sources(factory, client=client, nvd_api_key="secret-key")
    assert [s.id for s in sources] == [
        "kev",
        "nvd",
        "epss",
        "osv",
        "cve_org",
        "vulnrichment",
        "cwe",
    ]
    results = research(LOG4J, sources)
    assert [(r.source, r.status) for r in results] == [
        ("kev", "ok"),
        ("nvd", "ok"),
        ("epss", "ok"),
        ("osv", "no_data"),
        ("cve_org", "ok"),
        ("vulnrichment", "ok"),
        ("cwe", "ok"),
    ]
    assert all("secret-key" not in (r.message or "") for r in results)
