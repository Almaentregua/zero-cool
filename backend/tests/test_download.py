"""Tests for the cached, resumable-safe download helper (no real network)."""

from pathlib import Path

import httpx
import pytest

from zero_cool_api.http import FetchError, download_if_changed


def client_for(
    responses: list[httpx.Response | Exception],
) -> tuple[httpx.Client, list[httpx.Request]]:
    seen: list[httpx.Request] = []
    queue = list(responses)

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        item = queue.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    return httpx.Client(transport=httpx.MockTransport(handler)), seen


def no_sleep(_: float) -> None:
    return None


def test_downloads_and_stores_etag(tmp_path: Path) -> None:
    client, _ = client_for([httpx.Response(200, content=b"data", headers={"ETag": '"v1"'})])
    dest = tmp_path / "sub" / "f.zip"
    assert download_if_changed(client, "https://x.test/f.zip", dest) is True
    assert dest.read_bytes() == b"data"
    assert (tmp_path / "sub" / "f.zip.etag").read_text() == '"v1"'
    assert not (tmp_path / "sub" / "f.zip.part").exists()


def test_unchanged_file_is_not_downloaded_again(tmp_path: Path) -> None:
    dest = tmp_path / "f.zip"
    client, seen = client_for(
        [httpx.Response(200, content=b"data", headers={"ETag": '"v1"'}), httpx.Response(304)]
    )
    download_if_changed(client, "https://x.test/f.zip", dest)
    assert download_if_changed(client, "https://x.test/f.zip", dest) is False
    assert seen[0].headers.get("If-None-Match") is None
    assert seen[1].headers["If-None-Match"] == '"v1"'
    assert dest.read_bytes() == b"data"


def test_etag_is_ignored_when_the_file_is_gone(tmp_path: Path) -> None:
    dest = tmp_path / "f.zip"
    (tmp_path / "f.zip.etag").write_text('"old"')
    client, seen = client_for([httpx.Response(200, content=b"new")])
    assert download_if_changed(client, "https://x.test/f.zip", dest) is True
    assert "If-None-Match" not in seen[0].headers


def test_retries_transient_errors(tmp_path: Path) -> None:
    client, seen = client_for(
        [httpx.Response(503), httpx.ConnectError("boom"), httpx.Response(200, content=b"ok")]
    )
    waits: list[float] = []
    dest = tmp_path / "f.zip"
    assert download_if_changed(client, "https://x.test", dest, sleep=waits.append) is True
    assert len(seen) == 3
    assert waits == [1.0, 2.0]


def test_gives_up_and_leaves_no_partial_file(tmp_path: Path) -> None:
    client, _ = client_for([httpx.Response(500)] * 2)
    dest = tmp_path / "f.zip"
    with pytest.raises(FetchError, match="after 2 attempts"):
        download_if_changed(client, "https://x.test", dest, max_retries=1, sleep=no_sleep)
    assert list(tmp_path.iterdir()) == []


def test_client_error_is_not_retried(tmp_path: Path) -> None:
    client, seen = client_for([httpx.Response(404)])
    with pytest.raises(FetchError, match="404"):
        download_if_changed(client, "https://x.test", tmp_path / "f.zip", sleep=no_sleep)
    assert len(seen) == 1


def test_too_large_download_is_aborted_and_cleaned_up(tmp_path: Path) -> None:
    client, _ = client_for([httpx.Response(200, content=b"x" * 100)])
    dest = tmp_path / "f.zip"
    with pytest.raises(FetchError, match="exceeds"):
        download_if_changed(client, "https://x.test", dest, max_bytes=10)
    assert list(tmp_path.iterdir()) == []


def test_failed_refresh_keeps_the_previous_file(tmp_path: Path) -> None:
    dest = tmp_path / "f.zip"
    dest.write_bytes(b"old")
    client, _ = client_for([httpx.Response(500)])
    with pytest.raises(FetchError):
        download_if_changed(client, "https://x.test", dest, max_retries=0, sleep=no_sleep)
    assert dest.read_bytes() == b"old"
