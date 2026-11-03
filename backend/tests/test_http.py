"""Tests for the retrying HTTP helper (no real network)."""

import httpx
import pytest

from zero_cool_api.http import FetchError, get_json


def make_client(responses: list[httpx.Response | Exception]) -> tuple[httpx.Client, list[int]]:
    calls: list[int] = []
    queue = list(responses)

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        item = queue.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    return httpx.Client(transport=httpx.MockTransport(handler)), calls


def test_returns_json_on_success() -> None:
    client, calls = make_client([httpx.Response(200, json={"a": 1})])
    assert get_json(client, "https://x.test") == {"a": 1}
    assert len(calls) == 1


def test_retries_then_succeeds_with_exponential_backoff() -> None:
    client, calls = make_client(
        [httpx.Response(503), httpx.ConnectError("boom"), httpx.Response(200, json=[1])]
    )
    waits: list[float] = []
    assert get_json(client, "https://x.test", sleep=waits.append) == [1]
    assert len(calls) == 3
    assert waits == [1.0, 2.0]


def test_retry_after_header_is_respected() -> None:
    client, _ = make_client(
        [httpx.Response(429, headers={"Retry-After": "7"}), httpx.Response(200, json={})]
    )
    waits: list[float] = []
    get_json(client, "https://x.test", sleep=waits.append)
    assert waits == [7.0]


def test_gives_up_after_max_retries() -> None:
    client, calls = make_client([httpx.Response(500)] * 3)
    with pytest.raises(FetchError, match="after 3 attempts"):
        get_json(client, "https://x.test", max_retries=2, sleep=lambda _: None)
    assert len(calls) == 3


def test_client_error_is_not_retried() -> None:
    client, calls = make_client([httpx.Response(404)])
    with pytest.raises(FetchError, match="404"):
        get_json(client, "https://x.test", sleep=lambda _: None)
    assert len(calls) == 1


def test_invalid_json_raises() -> None:
    client, _ = make_client([httpx.Response(200, text="<html>")])
    with pytest.raises(FetchError, match="invalid JSON"):
        get_json(client, "https://x.test")
