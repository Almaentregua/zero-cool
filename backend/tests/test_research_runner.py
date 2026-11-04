"""Tests for the research source interface and runner (no real sources involved)."""

import threading

import pytest

from zero_cool_api.http import FetchError
from zero_cool_api.research.base import Fetched, normalize_cve_id
from zero_cool_api.research.runner import ResultCache, research


class FakeSource:
    """Configurable source: returns ``fetched`` or raises ``error``."""

    def __init__(
        self,
        source_id: str,
        fetched: Fetched | None = None,
        error: Exception | None = None,
        ttl: int = 60,
        block: threading.Event | None = None,
    ) -> None:
        self.id = source_id
        self.name = source_id.upper()
        self.cache_ttl_seconds = ttl
        self.calls = 0
        self._fetched = fetched or Fetched(data={"x": 1})
        self._error = error
        self._block = block

    def fetch(self, cve_id: str) -> Fetched:
        self.calls += 1
        if self._block is not None:
            self._block.wait(timeout=5)
        if self._error is not None:
            raise self._error
        return self._fetched


def test_normalize_cve_id() -> None:
    assert normalize_cve_id(" cve-2021-44228 ") == "CVE-2021-44228"
    for bad in ["", "CVE-21-1", "CVE-2021-12", "../etc/passwd", "CVE-2021-1234; DROP"]:
        with pytest.raises(ValueError):
            normalize_cve_id(bad)


def test_origin_url_must_be_http() -> None:
    assert Fetched(origin_url="https://nvd.nist.gov/x").origin_url == "https://nvd.nist.gov/x"
    with pytest.raises(ValueError):
        Fetched(origin_url="javascript:alert(1)")


def test_invalid_cve_calls_no_source() -> None:
    source = FakeSource("a")
    with pytest.raises(ValueError):
        research("nope", [source])
    assert source.calls == 0


def test_results_keep_source_order_and_status() -> None:
    sources = [
        FakeSource("a", Fetched(data={"v": 1}, origin_url="https://a.example/1")),
        FakeSource("b", Fetched(data=None, message="Not listed")),
    ]
    results = research("cve-2021-44228", sources)
    assert [r.source for r in results] == ["a", "b"]
    assert results[0].status == "ok"
    assert results[0].data == {"v": 1}
    assert results[0].origin_url == "https://a.example/1"
    assert results[0].cve_id == "CVE-2021-44228"
    assert results[1].status == "no_data"
    assert results[1].message == "Not listed"
    assert results[1].data is None


def test_no_data_gets_a_default_message() -> None:
    result = research("CVE-2021-44228", [FakeSource("a", Fetched(data=None))])[0]
    assert result.status == "no_data"
    assert result.message == "The source has no information about this CVE"


def test_failing_source_does_not_affect_the_others() -> None:
    sources = [
        FakeSource("bad", error=FetchError("boom secret-token", status_code=503)),
        FakeSource("crash", error=RuntimeError("secret-token leaked?")),
        FakeSource("good"),
    ]
    bad, crash, good = research("CVE-2021-44228", sources)
    assert bad.status == "error"
    assert bad.message is not None and "HTTP 503" in bad.message
    assert crash.status == "error"
    assert good.status == "ok"
    for failed in (bad, crash):
        assert failed.message is not None and "secret-token" not in failed.message


def test_slow_source_times_out() -> None:
    release = threading.Event()
    sources = [FakeSource("slow", block=release), FakeSource("fast")]
    try:
        slow, fast = research("CVE-2021-44228", sources, timeout_seconds=0.1)
    finally:
        release.set()
    assert slow.status == "error"
    assert slow.message is not None and "did not answer" in slow.message
    assert fast.status == "ok"


def test_cache_avoids_a_second_call_and_force_bypasses_it() -> None:
    source = FakeSource("a")
    cache = ResultCache()
    research("CVE-2021-44228", [source], cache=cache)
    research("CVE-2021-44228", [source], cache=cache)
    assert source.calls == 1
    research("CVE-2021-44228", [source], cache=cache, force=True)
    assert source.calls == 2


def test_cache_entries_expire() -> None:
    now = [0.0]
    cache = ResultCache(clock=lambda: now[0])
    source = FakeSource("a", ttl=10)
    research("CVE-2021-44228", [source], cache=cache)
    now[0] = 9.0
    research("CVE-2021-44228", [source], cache=cache)
    assert source.calls == 1
    now[0] = 10.0
    research("CVE-2021-44228", [source], cache=cache)
    assert source.calls == 2


def test_errors_are_not_cached() -> None:
    source = FakeSource("a", error=FetchError("down"))
    cache = ResultCache()
    research("CVE-2021-44228", [source], cache=cache)
    research("CVE-2021-44228", [source], cache=cache)
    assert source.calls == 2
