"""HTTP helper with retries and exponential backoff for external APIs."""

import logging
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger(__name__)

RETRYABLE_STATUS = {429, 500, 502, 503, 504}
MAX_BACKOFF_SECONDS = 60.0


class FetchError(Exception):
    """Raised when an external request fails after all retries.

    Attributes:
        status_code: HTTP status of the failing response, if there was one.
    """

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


def get_json(
    client: httpx.Client,
    url: str,
    *,
    params: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    max_retries: int = 4,
    backoff_seconds: float = 1.0,
    sleep: Callable[[float], None] = time.sleep,
) -> Any:
    """GET a URL and parse the JSON body, retrying transient failures.

    Retries on network errors and on HTTP 429/5xx, waiting ``backoff_seconds``
    doubled after each attempt (capped at 60 s). A numeric ``Retry-After``
    header takes precedence. Other 4xx responses fail immediately.

    Parameters:
        client: HTTP client to use (inject a mock transport in tests).
        url: Absolute URL.
        params: Query string parameters.
        headers: Extra request headers. Never log them: they may hold API keys.
        max_retries: Retries after the first attempt.
        backoff_seconds: Initial wait between attempts.
        sleep: Function used to wait; injectable so tests do not really sleep.

    Returns:
        The decoded JSON body.

    Raises:
        FetchError: On a non-retryable error status, an invalid JSON body, or
            when every attempt failed.
    """
    delay = backoff_seconds
    last_error = "unknown error"
    for attempt in range(max_retries + 1):
        wait = delay
        try:
            response = client.get(url, params=params, headers=headers)
        except httpx.TransportError as exc:
            last_error = f"network error: {type(exc).__name__}"
        else:
            if response.status_code in RETRYABLE_STATUS:
                last_error = f"HTTP {response.status_code}"
                retry_after = response.headers.get("Retry-After", "")
                if retry_after.isdigit():
                    wait = min(float(retry_after), MAX_BACKOFF_SECONDS)
            elif response.is_error:
                raise FetchError(
                    f"GET {url} failed: HTTP {response.status_code}", response.status_code
                )
            else:
                try:
                    return response.json()
                except ValueError as exc:
                    raise FetchError(f"GET {url} returned invalid JSON") from exc
        if attempt < max_retries:
            logger.warning("GET %s failed (%s); retrying in %.1fs", url, last_error, wait)
            sleep(wait)
            delay = min(delay * 2, MAX_BACKOFF_SECONDS)
    raise FetchError(f"GET {url} failed after {max_retries + 1} attempts: {last_error}")


def download_if_changed(
    client: httpx.Client,
    url: str,
    dest: Path,
    *,
    max_bytes: int = 1_000_000_000,
    max_retries: int = 4,
    backoff_seconds: float = 1.0,
    sleep: Callable[[float], None] = time.sleep,
) -> bool:
    """Download a large file unless the server says it has not changed.

    The server's ``ETag`` is kept next to the file (``<dest>.etag``) and sent back
    as ``If-None-Match``, so an unchanged file is not downloaded again. The data is
    written to a temporary file and renamed only when complete, so a failed
    download never leaves a partial file in place. Retries like :func:`get_json`.

    Parameters:
        client: HTTP client.
        url: Absolute URL.
        dest: Where to keep the file (parent directories are created).
        max_bytes: Abort if the download grows beyond this size.
        max_retries: Retries after the first attempt.
        backoff_seconds: Initial wait between attempts, doubled each time.
        sleep: Function used to wait; injectable for tests.

    Returns:
        ``True`` if a new file was downloaded, ``False`` if the cached one is current.

    Raises:
        FetchError: On a non-retryable error status, a file larger than
            ``max_bytes``, or when every attempt failed.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    etag_path = dest.with_name(dest.name + ".etag")
    tmp_path = dest.with_name(dest.name + ".part")
    delay = backoff_seconds
    last_error = "unknown error"
    for attempt in range(max_retries + 1):
        headers: dict[str, str] = {}
        if dest.exists() and etag_path.exists():
            headers["If-None-Match"] = etag_path.read_text(encoding="utf-8").strip()
        try:
            with client.stream("GET", url, headers=headers) as response:
                if response.status_code == 304:
                    return False
                if response.status_code in RETRYABLE_STATUS:
                    last_error = f"HTTP {response.status_code}"
                elif response.is_error:
                    raise FetchError(
                        f"GET {url} failed: HTTP {response.status_code}", response.status_code
                    )
                else:
                    size = 0
                    with tmp_path.open("wb") as out:
                        for chunk in response.iter_bytes(1024 * 1024):
                            size += len(chunk)
                            if size > max_bytes:
                                raise FetchError(f"GET {url} exceeds {max_bytes} bytes")
                            out.write(chunk)
                    tmp_path.replace(dest)
                    etag = response.headers.get("ETag")
                    if etag:
                        etag_path.write_text(etag, encoding="utf-8")
                    else:
                        etag_path.unlink(missing_ok=True)
                    return True
        except httpx.TransportError as exc:
            last_error = f"network error: {type(exc).__name__}"
        except FetchError:
            tmp_path.unlink(missing_ok=True)
            raise
        tmp_path.unlink(missing_ok=True)
        if attempt < max_retries:
            logger.warning("GET %s failed (%s); retrying in %.1fs", url, last_error, delay)
            sleep(delay)
            delay = min(delay * 2, MAX_BACKOFF_SECONDS)
    raise FetchError(f"GET {url} failed after {max_retries + 1} attempts: {last_error}")
