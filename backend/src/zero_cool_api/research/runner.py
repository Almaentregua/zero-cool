"""Run research sources for a CVE: in parallel, with a timeout, a cache and isolated failures."""

import logging
import threading
import time
from collections.abc import Callable, Sequence
from concurrent.futures import Future, ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from datetime import UTC, datetime
from typing import Any

from zero_cool_api.http import FetchError
from zero_cool_api.research.base import ResearchSource, SourceResult, Status, normalize_cve_id

DEFAULT_TIMEOUT_SECONDS = 15.0

logger = logging.getLogger(__name__)


class ResultCache:
    """Thread-safe in-memory cache of source results with a per-entry expiry.

    Only ``ok`` and ``no_data`` results are cached; errors are always retried.
    """

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._items: dict[tuple[str, str], tuple[float, SourceResult]] = {}

    def get(self, source_id: str, cve_id: str) -> SourceResult | None:
        """Return a cached result that has not expired, or ``None``."""
        with self._lock:
            entry = self._items.get((source_id, cve_id))
            if entry is None:
                return None
            expires_at, result = entry
            if self._clock() >= expires_at:
                del self._items[(source_id, cve_id)]
                return None
            return result

    def put(self, result: SourceResult, ttl_seconds: int) -> None:
        """Store a result for ``ttl_seconds`` seconds (errors are ignored)."""
        if result.status == "error":
            return
        with self._lock:
            self._items[(result.source, result.cve_id)] = (self._clock() + ttl_seconds, result)


def _result(
    source: ResearchSource,
    cve_id: str,
    status: Status,
    *,
    message: str | None = None,
    origin_url: str | None = None,
    data: dict[str, Any] | None = None,
) -> SourceResult:
    """Build a ``SourceResult`` for ``source`` stamped with the current time."""
    return SourceResult(
        source=source.id,
        source_name=source.name,
        cve_id=cve_id,
        status=status,
        message=message,
        origin_url=origin_url,
        retrieved_at=datetime.now(UTC),
        data=data,
    )


def _query(source: ResearchSource, cve_id: str) -> SourceResult:
    """Call one source and turn its answer, or its failure, into a ``SourceResult``."""
    try:
        fetched = source.fetch(cve_id)
    except FetchError as exc:
        status = f" (HTTP {exc.status_code})" if exc.status_code else ""
        logger.warning("Source %s failed for %s: %s", source.id, cve_id, exc)
        return _result(source, cve_id, "error", message=f"The source could not be reached{status}")
    except Exception:
        # A broken source must never break the whole investigation. The details go to the
        # log only: they could contain request data we do not want to show.
        logger.exception("Source %s crashed for %s", source.id, cve_id)
        return _result(source, cve_id, "error", message="Unexpected error in this source")
    if fetched.data is None:
        return _result(
            source,
            cve_id,
            "no_data",
            message=fetched.message or "The source has no information about this CVE",
            origin_url=fetched.origin_url,
        )
    return _result(source, cve_id, "ok", data=fetched.data, origin_url=fetched.origin_url)


def research(
    raw_cve_id: str,
    sources: Sequence[ResearchSource],
    *,
    cache: ResultCache | None = None,
    force: bool = False,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> list[SourceResult]:
    """Ask every source about a CVE and return one result per source.

    Sources run in parallel. One failing or slow source only affects its own result.

    Parameters:
        raw_cve_id: CVE id as typed by the user; validated and normalized here.
        sources: Sources to consult; results keep this order.
        cache: Result cache. ``None`` disables caching.
        force: Ignore cached results (a manual refresh) and store the new ones.
        timeout_seconds: Maximum wait for each source. A source that exceeds it is reported
            as an error; its thread cannot be killed and finishes in the background.

    Returns:
        One ``SourceResult`` per source, in the order of ``sources``.

    Raises:
        ValueError: If ``raw_cve_id`` is not a valid CVE id (no source is called).
    """
    cve_id = normalize_cve_id(raw_cve_id)
    results: dict[str, SourceResult] = {}
    pending: list[ResearchSource] = []
    for source in sources:
        cached = None if force or cache is None else cache.get(source.id, cve_id)
        if cached is not None:
            results[source.id] = cached
        else:
            pending.append(source)

    if pending:
        # No `with` block: its exit would wait for hung threads and defeat the timeout.
        executor = ThreadPoolExecutor(max_workers=len(pending))
        try:
            futures: dict[str, Future[SourceResult]] = {
                s.id: executor.submit(_query, s, cve_id) for s in pending
            }
            deadline = time.monotonic() + timeout_seconds
            for source in pending:
                remaining = max(0.0, deadline - time.monotonic())
                try:
                    result = futures[source.id].result(timeout=remaining)
                except FutureTimeout:
                    logger.warning("Source %s timed out for %s", source.id, cve_id)
                    result = _result(
                        source,
                        cve_id,
                        "error",
                        message=f"The source did not answer within {timeout_seconds:g} s",
                    )
                if cache is not None:
                    cache.put(result, source.cache_ttl_seconds)
                results[source.id] = result
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

    return [results[s.id] for s in sources]
