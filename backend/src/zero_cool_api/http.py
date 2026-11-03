"""HTTP helper with retries and exponential backoff for external APIs."""

import logging
import time
from collections.abc import Callable
from typing import Any

import httpx

logger = logging.getLogger(__name__)

RETRYABLE_STATUS = {429, 500, 502, 503, 504}
MAX_BACKOFF_SECONDS = 60.0


class FetchError(Exception):
    """Raised when an external request fails after all retries."""


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
                raise FetchError(f"GET {url} failed: HTTP {response.status_code}")
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
