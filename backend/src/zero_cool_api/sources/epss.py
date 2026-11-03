"""EPSS (FIRST) source: fetch exploitation probabilities in batches."""

import logging
from collections.abc import Callable, Iterable
from typing import Any

import httpx
from pydantic import BaseModel, Field

from zero_cool_api.http import FetchError, get_json
from zero_cool_api.sources.kev import CVE_RE

EPSS_URL = "https://api.first.org/data/v1/epss"
# The API returns at most 100 rows per page by default, so ask for 100 CVEs at a time.
BATCH_SIZE = 100

logger = logging.getLogger(__name__)


class EpssScore(BaseModel):
    """EPSS values for one CVE, both between 0 and 1."""

    cve_id: str
    score: float = Field(ge=0.0, le=1.0)
    percentile: float = Field(ge=0.0, le=1.0)


def parse_rows(payload: Any) -> list[EpssScore]:
    """Validate and normalize the rows of one EPSS response.

    Parameters:
        payload: Decoded JSON of an EPSS response.

    Returns:
        The valid scores. Malformed rows are skipped and counted in the log.

    Raises:
        FetchError: If the payload does not look like an EPSS response.
    """
    rows = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        raise FetchError("Unexpected EPSS payload: missing 'data' list")
    scores: list[EpssScore] = []
    skipped = 0
    for row in rows:
        try:
            cve = str(row["cve"]).strip().upper()
            if not CVE_RE.fullmatch(cve):
                raise ValueError("invalid CVE id")
            scores.append(
                EpssScore(cve_id=cve, score=float(row["epss"]), percentile=float(row["percentile"]))
            )
        except (KeyError, TypeError, ValueError):  # ValidationError is a ValueError
            skipped += 1
    if skipped:
        logger.warning("Skipped %d invalid EPSS rows", skipped)
    return scores


def fetch_epss(
    client: httpx.Client,
    cve_ids: Iterable[str],
    *,
    url: str = EPSS_URL,
    progress: Callable[[int, int], None] | None = None,
) -> dict[str, EpssScore]:
    """Fetch EPSS scores for many CVEs.

    Parameters:
        client: HTTP client.
        cve_ids: CVE ids to look up. Ids EPSS does not know are absent from the result.
        url: API URL (overridable for tests).
        progress: Optional callback ``(done, total)`` in CVEs.

    Returns:
        Scores keyed by CVE id.

    Raises:
        FetchError: If a request fails after retries or a payload is unexpected.
    """
    ids = sorted({c for c in cve_ids if CVE_RE.fullmatch(c)})
    result: dict[str, EpssScore] = {}
    for start in range(0, len(ids), BATCH_SIZE):
        batch = ids[start : start + BATCH_SIZE]
        payload = get_json(client, url, params={"cve": ",".join(batch), "limit": BATCH_SIZE})
        for score in parse_rows(payload):
            if score.cve_id in batch:  # ignore anything we did not ask for
                result[score.cve_id] = score
        if progress:
            progress(min(start + BATCH_SIZE, len(ids)), len(ids))
    return result
