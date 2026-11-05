"""Tests for the research endpoint (fake sources; no network, no real database)."""

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from zero_cool_api.api.deps import get_research_sources, get_result_cache
from zero_cool_api.http import FetchError
from zero_cool_api.main import app
from zero_cool_api.research.base import Fetched, ResearchSource
from zero_cool_api.research.runner import ResultCache


class FakeSource:
    def __init__(self, source_id: str, fetched: Fetched | None = None, fail: bool = False) -> None:
        self.id = source_id
        self.name = f"Source {source_id}"
        self.cache_ttl_seconds = 60
        self.calls = 0
        self._fetched = fetched or Fetched(
            data={"v": 1}, origin_url=f"https://{source_id}.example/"
        )
        self._fail = fail

    def fetch(self, cve_id: str) -> Fetched:
        self.calls += 1
        if self._fail:
            raise FetchError("down")
        return self._fetched


@pytest.fixture
def sources() -> list[FakeSource]:
    return [
        FakeSource("a"),
        FakeSource("b", Fetched(data=None, message="Nothing")),
        FakeSource("c", fail=True),
    ]


@pytest.fixture
def client(sources: list[FakeSource]) -> Iterator[TestClient]:
    cache = ResultCache()
    typed: list[ResearchSource] = list(sources)
    app.dependency_overrides[get_research_sources] = lambda: typed
    app.dependency_overrides[get_result_cache] = lambda: cache
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_one_block_per_source_and_a_summary(client: TestClient) -> None:
    body = client.get("/api/research/cve-2021-44228").json()
    assert body["cve_id"] == "CVE-2021-44228"
    assert body["sources"] == [
        {"source": "a", "source_name": "Source a", "status": "ok"},
        {"source": "b", "source_name": "Source b", "status": "no_data"},
        {"source": "c", "source_name": "Source c", "status": "error"},
    ]
    a, b, c = body["results"]
    assert a["data"] == {"v": 1} and a["origin_url"] == "https://a.example/"
    assert b["data"] is None and b["message"] == "Nothing"
    assert c["status"] == "error" and c["data"] is None
    assert a["retrieved_at"]


def test_invalid_id_is_422_and_calls_nothing(client: TestClient, sources: list[FakeSource]) -> None:
    for bad in ["nope", "CVE-1-1", "CVE-2021-44228%3Bx"]:
        assert client.get(f"/api/research/{bad}").status_code == 422
    assert all(s.calls == 0 for s in sources)


def test_results_are_cached_and_refresh_bypasses_the_cache(
    client: TestClient, sources: list[FakeSource]
) -> None:
    client.get("/api/research/CVE-2021-44228")
    client.get("/api/research/CVE-2021-44228")
    assert sources[0].calls == 1
    assert sources[2].calls == 2  # errors are never cached
    client.get("/api/research/CVE-2021-44228?refresh=true")
    assert sources[0].calls == 2


def test_openapi_documents_the_endpoint() -> None:
    operation = app.openapi()["paths"]["/api/research/{cve_id}"]["get"]
    assert operation["summary"]
    assert operation["description"]
    assert "example" in operation["responses"]["200"]["content"]["application/json"]
