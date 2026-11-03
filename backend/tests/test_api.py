"""Tests for the vulnerability and technology endpoints (temporary database)."""

from collections.abc import Iterator
from datetime import date
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from zero_cool_api.api.routes import get_technologies
from zero_cool_api.db import create_db_engine, get_session, init_db
from zero_cool_api.main import app
from zero_cool_api.models import Reference, Vulnerability
from zero_cool_api.technologies import Product, Technology

TECHS = [
    Technology(
        name="Java",
        osv_ecosystems=["Maven"],
        products=[Product(vendor="Apache", product="Log4j2")],
    ),
    Technology(name="Empty", osv_ecosystems=[], products=[]),
]


def seed(session: Session) -> None:
    session.add_all(
        [
            Vulnerability(
                cve_id="CVE-2021-44228",
                title="Log4j RCE",
                description="JNDI lookup flaw in Log4j",
                vendor="Apache",
                product="Log4j2",
                is_kev=True,
                date_added=date(2021, 12, 10),
                ransomware_use=True,
                cvss_score=10.0,
                severity="CRITICAL",
                epss_score=0.97,
                references=[Reference(url="https://example.test/advisory")],
            ),
            Vulnerability(
                cve_id="CVE-2022-0001",
                title="Widget bug",
                description="100% broken_widget",
                vendor="Acme",
                product="Widget",
                is_kev=True,
                date_added=date(2022, 3, 1),
                ransomware_use=False,
                cvss_score=5.0,
                severity="MEDIUM",
                epss_score=0.1,
            ),
            Vulnerability(
                cve_id="CVE-2023-0002",
                title="Unscored",
                vendor="Apache",
                product="Tomcat",
                is_kev=True,
                date_added=date(2023, 5, 5),
            ),
        ]
    )
    session.commit()


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    engine = create_db_engine(tmp_path / "api.db")
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
    response = client.get("/api/vulnerabilities", params=params)
    assert response.status_code == 200, response.text
    return [i["cve_id"] for i in response.json()["items"]]


def test_list_default_sort_is_newest_first(client: TestClient) -> None:
    body = client.get("/api/vulnerabilities").json()
    assert [i["cve_id"] for i in body["items"]] == [
        "CVE-2023-0002",
        "CVE-2022-0001",
        "CVE-2021-44228",
    ]
    assert body["total"] == 3
    assert (body["page"], body["page_size"]) == (1, 25)


def test_missing_values_are_null_not_zero(client: TestClient) -> None:
    item = client.get("/api/vulnerabilities", params={"q": "Unscored"}).json()["items"][0]
    assert item["cvss_score"] is None
    assert item["epss_score"] is None
    assert item["severity"] is None
    assert item["ransomware_use"] is None


def test_date_filter_is_inclusive(client: TestClient) -> None:
    assert ids(client, added_from="2022-03-01", added_to="2022-03-01") == ["CVE-2022-0001"]
    assert ids(client, added_from="2022-01-01") == ["CVE-2023-0002", "CVE-2022-0001"]


def test_inverted_date_range_is_rejected(client: TestClient) -> None:
    response = client.get(
        "/api/vulnerabilities", params={"added_from": "2023-01-01", "added_to": "2022-01-01"}
    )
    assert response.status_code == 422


def test_technology_filter_and_labels(client: TestClient) -> None:
    assert ids(client, technology="java") == ["CVE-2021-44228"]  # case-insensitive
    item = client.get("/api/vulnerabilities", params={"technology": "Java"}).json()["items"][0]
    assert item["technologies"] == ["Java"]
    other = client.get("/api/vulnerabilities", params={"q": "Widget"}).json()["items"][0]
    assert other["technologies"] == []


def test_technology_without_products_matches_nothing(client: TestClient) -> None:
    assert ids(client, technology="Empty") == []


def test_unknown_technology_is_rejected_with_available_names(client: TestClient) -> None:
    response = client.get("/api/vulnerabilities", params={"technology": "Cobol"})
    assert response.status_code == 422
    assert "Java" in response.json()["detail"]


def test_vendor_and_product_contains(client: TestClient) -> None:
    assert ids(client, vendor="apach") == ["CVE-2023-0002", "CVE-2021-44228"]
    assert ids(client, vendor="apache", product="TOMCAT") == ["CVE-2023-0002"]


def test_cvss_severity_epss_ransomware_filters(client: TestClient) -> None:
    assert ids(client, min_cvss=6) == ["CVE-2021-44228"]
    assert ids(client, severity=["MEDIUM", "CRITICAL"]) == ["CVE-2022-0001", "CVE-2021-44228"]
    assert ids(client, min_epss=0.5) == ["CVE-2021-44228"]
    assert ids(client, ransomware="true") == ["CVE-2021-44228"]
    assert ids(client, ransomware="false") == ["CVE-2022-0001"]


@pytest.mark.parametrize(
    "params",
    [
        {"min_cvss": 11},
        {"min_epss": 2},
        {"severity": "SEVERE"},
        {"page": 0},
        {"page_size": 101},
        {"sort": "name"},
        {"added_from": "yesterday"},
    ],
)
def test_invalid_parameters_return_422(client: TestClient, params: dict[str, object]) -> None:
    response = client.get("/api/vulnerabilities", params=params)
    assert response.status_code == 422


def test_text_search_matches_several_fields_case_insensitively(client: TestClient) -> None:
    assert ids(client, q="cve-2022") == ["CVE-2022-0001"]
    assert ids(client, q="jndi") == ["CVE-2021-44228"]
    assert ids(client, q="WIDGET") == ["CVE-2022-0001"]


def test_search_wildcards_are_literal_and_injection_is_harmless(client: TestClient) -> None:
    assert ids(client, q="%") == ["CVE-2022-0001"]  # only the text containing a real '%'
    assert ids(client, q="_") == ["CVE-2022-0001"]  # only the text containing a real '_'
    assert ids(client, q="'; DROP TABLE vulnerabilities; --") == []
    assert len(ids(client)) == 3  # the table is still intact


def test_sorting_puts_missing_values_last_in_both_directions(client: TestClient) -> None:
    assert ids(client, sort="cvss", order="desc") == [
        "CVE-2021-44228",
        "CVE-2022-0001",
        "CVE-2023-0002",
    ]
    assert ids(client, sort="cvss", order="asc") == [
        "CVE-2022-0001",
        "CVE-2021-44228",
        "CVE-2023-0002",
    ]


def test_pagination(client: TestClient) -> None:
    first = client.get("/api/vulnerabilities", params={"page_size": 2}).json()
    assert len(first["items"]) == 2
    assert first["total"] == 3
    second = client.get("/api/vulnerabilities", params={"page_size": 2, "page": 2}).json()
    assert [i["cve_id"] for i in second["items"]] == ["CVE-2021-44228"]


def test_detail_includes_references_and_technologies(client: TestClient) -> None:
    body = client.get("/api/vulnerabilities/cve-2021-44228").json()  # lowercase accepted
    assert body["cve_id"] == "CVE-2021-44228"
    assert body["references"] == ["https://example.test/advisory"]
    assert body["technologies"] == ["Java"]
    assert body["description"] == "JNDI lookup flaw in Log4j"
    assert body["cvss_vector"] is None


def test_detail_404_and_422(client: TestClient) -> None:
    assert client.get("/api/vulnerabilities/CVE-1999-0001").status_code == 404
    assert client.get("/api/vulnerabilities/not-a-cve").status_code == 422


def test_technologies_endpoint(client: TestClient) -> None:
    body = client.get("/api/technologies").json()
    assert body[0] == {
        "name": "Java",
        "osv_ecosystems": ["Maven"],
        "products": ["Apache / Log4j2"],
    }


def test_openapi_documents_every_endpoint() -> None:
    paths = TestClient(app).get("/openapi.json").json()["paths"]
    for path in ("/api/vulnerabilities", "/api/vulnerabilities/{cve_id}", "/api/technologies"):
        operation = paths[path]["get"]
        assert operation["summary"]
        assert operation["description"]
