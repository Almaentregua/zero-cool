"""Tests for the report endpoints (fake sources, temporary database)."""

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from zero_cool_api.api.deps import get_research_sources, get_result_cache
from zero_cool_api.db import create_db_engine, get_session, init_db
from zero_cool_api.http import FetchError
from zero_cool_api.main import app
from zero_cool_api.research.base import Fetched, ResearchSource
from zero_cool_api.research.runner import ResultCache

LOG4J = "CVE-2021-44228"
OTHER = "CVE-2022-22965"


class FakeSource:
    """Source whose answer can be changed between calls."""

    def __init__(self, source_id: str, data: dict[str, object] | None) -> None:
        self.id = source_id
        self.name = f"Source {source_id}"
        self.cache_ttl_seconds = 3600
        self.data = data
        self.fail = False

    def fetch(self, cve_id: str) -> Fetched:
        if self.fail:
            raise FetchError("down")
        return Fetched(data=self.data, origin_url=f"https://{self.id}.example/{cve_id}")


@pytest.fixture
def fakes() -> list[FakeSource]:
    return [FakeSource("a", {"score": 1, "label": "x"}), FakeSource("b", None)]


@pytest.fixture
def client(tmp_path: Path, fakes: list[FakeSource]) -> Iterator[TestClient]:
    engine = create_db_engine(tmp_path / "t.db")
    init_db(engine)
    typed: list[ResearchSource] = list(fakes)
    cache = ResultCache()

    def session() -> Iterator[Session]:
        with Session(engine) as s:
            yield s

    app.dependency_overrides[get_session] = session
    app.dependency_overrides[get_research_sources] = lambda: typed
    app.dependency_overrides[get_result_cache] = lambda: cache
    yield TestClient(app)
    app.dependency_overrides.clear()


def create(client: TestClient, cves: list[str] | None = None) -> dict[str, object]:
    response = client.post(
        "/api/reports", json={"title": "Log4Shell", "cves": cves or [LOG4J], "notes": "# hi"}
    )
    assert response.status_code == 201, response.text
    body: dict[str, object] = response.json()
    return body


def test_create_saves_one_block_per_cve_and_source(client: TestClient) -> None:
    report = create(client, [LOG4J.lower(), OTHER, LOG4J])  # duplicate and lowercase
    assert report["cves"] == [LOG4J, OTHER]
    assert report["notes"] == "# hi"
    results = report["results"]
    assert isinstance(results, list)
    assert [(r["cve_id"], r["source"], r["status"]) for r in results] == [
        (LOG4J, "a", "ok"),
        (LOG4J, "b", "no_data"),
        (OTHER, "a", "ok"),
        (OTHER, "b", "no_data"),
    ]
    assert results[0]["source_name"] == "Source a"
    assert results[0]["data"] == {"score": 1, "label": "x"}
    assert results[0]["origin_url"] == f"https://a.example/{LOG4J}"


@pytest.mark.parametrize(
    "body",
    [
        {"title": "", "cves": [LOG4J]},
        {"title": "   ", "cves": [LOG4J]},
        {"title": "t", "cves": []},
        {"title": "t", "cves": ["nope"]},
        {"title": "t", "cves": [f"CVE-2021-{1000 + i}" for i in range(11)]},
    ],
)
def test_create_rejects_bad_input_and_saves_nothing(
    client: TestClient, body: dict[str, object]
) -> None:
    assert client.post("/api/reports", json=body).status_code == 422
    assert client.get("/api/reports").json() == []


def test_list_open_and_delete(client: TestClient) -> None:
    first = create(client)
    second = create(client, [OTHER])
    listed = client.get("/api/reports").json()
    assert [r["id"] for r in listed] == [second["id"], first["id"]]
    assert "notes" not in listed[0] and "results" not in listed[0]
    opened = client.get(f"/api/reports/{first['id']}").json()
    assert opened["results"][0]["data"] == {"score": 1, "label": "x"}
    assert client.delete(f"/api/reports/{first['id']}").status_code == 204
    assert client.get(f"/api/reports/{first['id']}").status_code == 404
    assert client.delete(f"/api/reports/{first['id']}").status_code == 404


def test_opening_a_report_does_not_query_the_sources(
    client: TestClient, fakes: list[FakeSource]
) -> None:
    report = create(client)
    fakes[0].data = {"score": 99}
    opened = client.get(f"/api/reports/{report['id']}").json()
    assert opened["results"][0]["data"] == {"score": 1, "label": "x"}  # still the snapshot


def test_patch_notes_title_status_and_cves(client: TestClient) -> None:
    report = create(client)
    url = f"/api/reports/{report['id']}"
    body = client.patch(
        url,
        json={"title": "New", "notes": "more", "status": "done", "add_cves": [OTHER]},
    ).json()
    assert (body["title"], body["notes"], body["status"]) == ("New", "more", "done")
    assert body["cves"] == [LOG4J, OTHER]
    assert len(body["results"]) == 4
    body = client.patch(url, json={"remove_cves": [LOG4J]}).json()
    assert body["cves"] == [OTHER]
    assert {r["cve_id"] for r in body["results"]} == {OTHER}


@pytest.mark.parametrize(
    "patch",
    [
        {"status": "weird"},
        {"title": " "},
        {"remove_cves": [LOG4J]},  # would leave the report empty
        {"add_cves": ["bad"]},
    ],
)
def test_patch_rejects_bad_input_without_changing_anything(
    client: TestClient, patch: dict[str, object]
) -> None:
    report = create(client)
    url = f"/api/reports/{report['id']}"
    assert client.patch(url, json=patch).status_code == 422
    after = client.get(url).json()
    assert after["title"] == "Log4Shell" and after["cves"] == [LOG4J]


def test_unknown_report_is_404(client: TestClient) -> None:
    assert client.get("/api/reports/999").status_code == 404
    assert client.patch("/api/reports/999", json={"notes": "x"}).status_code == 404
    assert client.post("/api/reports/999/refresh").status_code == 404


def test_refresh_reports_changes_and_ignores_the_cache(
    client: TestClient, fakes: list[FakeSource]
) -> None:
    report = create(client)
    fakes[0].data = {"score": 2, "label": "x"}
    fakes[1].data = {"found": True}
    body = client.post(f"/api/reports/{report['id']}/refresh").json()
    changes = {c["source"]: c for c in body["changes"]}
    assert changes["a"]["kind"] == "data" and changes["a"]["fields"] == ["score"]
    assert changes["b"]["kind"] == "status"
    assert (changes["b"]["before_status"], changes["b"]["after_status"]) == ("no_data", "ok")
    assert body["report"]["results"][0]["data"] == {"score": 2, "label": "x"}
    assert body["report"]["notes"] == "# hi"


def test_refresh_without_changes_reports_none(client: TestClient) -> None:
    report = create(client)
    assert client.post(f"/api/reports/{report['id']}/refresh").json()["changes"] == []


def test_failed_refresh_keeps_the_previous_snapshot(
    client: TestClient, fakes: list[FakeSource]
) -> None:
    report = create(client)
    fakes[0].fail = True
    body = client.post(f"/api/reports/{report['id']}/refresh").json()
    assert [(c["source"], c["kind"]) for c in body["changes"]] == [("a", "refresh_failed")]
    first = body["report"]["results"][0]
    assert first["status"] == "ok" and first["data"] == {"score": 1, "label": "x"}


def test_cors_allows_the_methods_the_reports_need() -> None:
    for method in ("POST", "PATCH", "DELETE"):
        response = TestClient(app).options(
            "/api/reports/1",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": method,
            },
        )
        assert response.status_code == 200
        assert method in response.headers["access-control-allow-methods"]


def test_openapi_documents_every_report_operation() -> None:
    paths = app.openapi()["paths"]
    for path in ("/api/reports", "/api/reports/{report_id}", "/api/reports/{report_id}/refresh"):
        for operation in paths[path].values():
            assert operation["summary"] and operation["description"]
