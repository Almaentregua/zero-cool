"""Tests for the advisory endpoints and the CVE detail link (temporary database)."""

from collections.abc import Iterator
from datetime import date, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from zero_cool_api.api.deps import get_technologies
from zero_cool_api.db import create_db_engine, get_session, init_db
from zero_cool_api.main import app
from zero_cool_api.models import (
    Advisory,
    AdvisoryCve,
    AdvisoryPackage,
    AdvisoryReference,
    Vulnerability,
)
from zero_cool_api.technologies import Technology

TECHS = [
    Technology(name="Java", osv_ecosystems=["Maven"], products=[]),
    Technology(name="Node.js", osv_ecosystems=["npm"], products=[]),
    Technology(name="Empty", osv_ecosystems=[], products=[]),
]
LOG4J = "GHSA-jfh8-c2jp-5v3q"
EXPRESS = "GHSA-aaaa-bbbb-cccc"
NOCVE = "GHSA-bbbb-cccc-dddd"


def seed(session: Session) -> None:
    session.add(Vulnerability(cve_id="CVE-2021-44228", is_kev=True, date_added=date(2021, 12, 10)))
    session.add(Vulnerability(cve_id="CVE-2020-0001", is_kev=True))  # has no advisory
    session.add_all(
        [
            Advisory(
                id=LOG4J,
                summary="Remote code injection in Log4j",
                details="# Details\n<script>alert(1)</script>",
                severity="CRITICAL",
                cvss_vector="CVSS:3.1/AV:N",
                published_at=datetime(2021, 12, 10, 0, 40),
                epss_score=0.99,
                epss_percentile=1.0,
                github_reviewed=True,
                cves=[AdvisoryCve(cve_id="CVE-2021-44228"), AdvisoryCve(cve_id="CVE-2021-9999")],
                packages=[
                    AdvisoryPackage(
                        ecosystem="Maven",
                        name="org.apache.logging.log4j:log4j-core",
                        ranges_json='[{"type": "ECOSYSTEM", "events": [{"fixed": "2.15.0"}]}]',
                        fixed_versions="2.12.2, 2.15.0",
                    )
                ],
                references=[AdvisoryReference(url="https://example.test/log4j")],
            ),
            Advisory(
                id=EXPRESS,
                summary="Open redirect in express",
                severity="MEDIUM",
                published_at=datetime(2022, 6, 1),
                epss_score=0.05,
                cves=[AdvisoryCve(cve_id="CVE-2022-0001")],
                packages=[AdvisoryPackage(ecosystem="npm", name="express", ranges_json="not json")],
            ),
            Advisory(
                id=NOCVE,
                summary="Prototype pollution in 100%_lodash",
                severity="HIGH",
                published_at=datetime(2023, 1, 15),
                packages=[AdvisoryPackage(ecosystem="npm", name="lodash")],
            ),
        ]
    )
    session.commit()


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    engine = create_db_engine(tmp_path / "adv.db")
    init_db(engine)
    with Session(engine) as session:
        seed(session)

    def override_session() -> Iterator[Session]:
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_session] = override_session
    app.dependency_overrides[get_technologies] = lambda: TECHS
    yield TestClient(app)
    app.dependency_overrides.clear()


def ids(client: TestClient, **params: object) -> list[str]:
    response = client.get("/api/advisories", params=params)
    assert response.status_code == 200, response.text
    return [i["id"] for i in response.json()["items"]]


def test_list_default_order_is_newest_published_first(client: TestClient) -> None:
    body = client.get("/api/advisories").json()
    assert [i["id"] for i in body["items"]] == [NOCVE, EXPRESS, LOG4J]
    assert body["total"] == 3


def test_list_item_fields_and_missing_values(client: TestClient) -> None:
    items = {i["id"]: i for i in client.get("/api/advisories").json()["items"]}
    log4j = items[LOG4J]
    assert log4j["cves"] == ["CVE-2021-44228", "CVE-2021-9999"]
    assert log4j["technologies"] == ["Java"]
    assert log4j["packages"] == [
        {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"}
    ]
    nocve = items[NOCVE]
    assert nocve["cves"] == []
    assert nocve["epss_score"] is None  # not zero
    assert nocve["github_reviewed"] is None


def test_technology_filter_uses_ecosystems(client: TestClient) -> None:
    assert ids(client, technology="java") == [LOG4J]
    assert ids(client, technology="Node.js") == [NOCVE, EXPRESS]
    assert ids(client, technology=["Java", "Node.js"]) == [NOCVE, EXPRESS, LOG4J]
    assert ids(client, technology="Empty") == []


def test_unknown_technology_is_rejected_with_available_names(client: TestClient) -> None:
    response = client.get("/api/advisories", params={"technology": "Cobol"})
    assert response.status_code == 422
    assert "Java" in response.json()["detail"]


def test_package_severity_epss_and_cve_filters(client: TestClient) -> None:
    assert ids(client, package="LOG4J-CORE") == [LOG4J]
    assert ids(client, severity=["HIGH", "CRITICAL"]) == [NOCVE, LOG4J]
    assert ids(client, min_epss=0.5) == [LOG4J]
    assert ids(client, has_cve="true") == [EXPRESS, LOG4J]
    assert ids(client, has_cve="false") == [NOCVE]


def test_published_date_filters_are_inclusive(client: TestClient) -> None:
    assert ids(client, published_from="2022-06-01", published_to="2022-06-01") == [EXPRESS]
    assert ids(client, published_from="2022-01-01") == [NOCVE, EXPRESS]
    response = client.get(
        "/api/advisories", params={"published_from": "2023-01-01", "published_to": "2022-01-01"}
    )
    assert response.status_code == 422


def test_text_search_covers_id_summary_cve_and_package(client: TestClient) -> None:
    assert ids(client, q="jfh8") == [LOG4J]
    assert ids(client, q="REDIRECT") == [EXPRESS]
    assert ids(client, q="cve-2022-0001") == [EXPRESS]
    assert ids(client, q="lodash") == [NOCVE]


def test_search_wildcards_are_literal_and_injection_is_harmless(client: TestClient) -> None:
    assert ids(client, q="%") == [NOCVE]
    assert ids(client, q="_") == [NOCVE]
    assert ids(client, q="'; DROP TABLE advisories; --") == []
    assert len(ids(client)) == 3


def test_sorting_by_epss_puts_missing_last(client: TestClient) -> None:
    assert ids(client, sort="epss", order="desc") == [LOG4J, EXPRESS, NOCVE]
    assert ids(client, sort="epss", order="asc") == [EXPRESS, LOG4J, NOCVE]


@pytest.mark.parametrize(
    "params",
    [
        {"min_epss": 2},
        {"severity": "SEVERE"},
        {"page": 0},
        {"page_size": 101},
        {"sort": "severity"},
    ],
)
def test_invalid_parameters_return_422(client: TestClient, params: dict[str, object]) -> None:
    assert client.get("/api/advisories", params=params).status_code == 422


def test_pagination(client: TestClient) -> None:
    body = client.get("/api/advisories", params={"page_size": 2, "page": 2}).json()
    assert [i["id"] for i in body["items"]] == [LOG4J]
    assert body["total"] == 3


def test_detail(client: TestClient) -> None:
    body = client.get(f"/api/advisories/{LOG4J}").json()
    assert body["severity"] == "CRITICAL"
    assert body["cvss_vector"] == "CVSS:3.1/AV:N"
    assert body["details"] == "# Details\n<script>alert(1)</script>"  # raw text, never rendered
    assert body["references"] == ["https://example.test/log4j"]
    assert body["technologies"] == ["Java"]
    package = body["packages"][0]
    assert package["fixed_versions"] == ["2.12.2", "2.15.0"]
    assert package["ranges"] == [{"type": "ECOSYSTEM", "events": [{"fixed": "2.15.0"}]}]
    assert body["cves"] == [
        {"cve_id": "CVE-2021-44228", "in_database": True},
        {"cve_id": "CVE-2021-9999", "in_database": False},
    ]


def test_detail_tolerates_unreadable_ranges_and_missing_data(client: TestClient) -> None:
    body = client.get(f"/api/advisories/{EXPRESS}").json()
    assert body["packages"][0]["ranges"] == []
    assert body["packages"][0]["fixed_versions"] == []
    assert body["cvss_vector"] is None
    assert body["details"] is None


def test_detail_id_is_case_insensitive_404_and_422(client: TestClient) -> None:
    assert client.get(f"/api/advisories/{LOG4J.upper()}").status_code == 200
    assert client.get("/api/advisories/GHSA-zzzz-zzzz-zzzz").status_code == 404
    assert client.get("/api/advisories/not-an-id").status_code == 422
    assert client.get("/api/advisories/CVE-2021-44228").status_code == 422


def test_cve_detail_lists_related_advisories(client: TestClient) -> None:
    body = client.get("/api/vulnerabilities/CVE-2021-44228").json()
    assert body["advisories"] == [
        {
            "id": LOG4J,
            "summary": "Remote code injection in Log4j",
            "severity": "CRITICAL",
            "packages": [{"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"}],
        }
    ]


def test_cve_without_advisories_has_an_empty_list(client: TestClient) -> None:
    assert client.get("/api/vulnerabilities/CVE-2020-0001").json()["advisories"] == []


def test_openapi_documents_the_advisory_endpoints() -> None:
    paths = TestClient(app).get("/openapi.json").json()["paths"]
    for path in ("/api/advisories", "/api/advisories/{advisory_id}"):
        assert paths[path]["get"]["summary"]
        assert paths[path]["get"]["description"]
