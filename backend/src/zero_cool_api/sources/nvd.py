"""NVD (NIST) source: fetch one CVE, validate and normalize it."""

import logging
import time
from collections.abc import Callable
from datetime import datetime
from typing import Any

import httpx
from pydantic import BaseModel, ValidationError

from zero_cool_api.http import FetchError, get_json
from zero_cool_api.models import severity_from_cvss
from zero_cool_api.sources.kev import clean_text

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# NVD allows 50 requests / 30 s with an API key and 5 / 30 s without.
INTERVAL_WITH_KEY = 0.65
INTERVAL_WITHOUT_KEY = 6.5
# Newest CVSS version first; the first version present is used.
METRIC_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")
MAX_REFERENCES = 100

logger = logging.getLogger(__name__)


class NvdData(BaseModel):
    """Normalized NVD data for one CVE. ``None`` means NVD has no such data."""

    cve_id: str
    description: str | None
    cvss_score: float | None
    cvss_vector: str | None
    severity: str | None
    published_at: datetime | None
    modified_at: datetime | None
    references: list[str]


def _pick_cvss(metrics: Any) -> tuple[float | None, str | None]:
    """Choose the CVSS score and vector from NVD's ``metrics`` object.

    Uses the newest CVSS version available and, within it, prefers NVD's own
    ("Primary") rating over those from other sources.

    Parameters:
        metrics: The ``metrics`` object of an NVD CVE record.

    Returns:
        ``(score, vector)``, or ``(None, None)`` when no usable rating exists.
    """
    if not isinstance(metrics, dict):
        return None, None
    for key in METRIC_KEYS:
        items = metrics.get(key)
        if not isinstance(items, list) or not items:
            continue
        ordered = sorted(
            (i for i in items if isinstance(i, dict)),
            key=lambda i: i.get("type") != "Primary",
        )
        for item in ordered:
            data = item.get("cvssData")
            if not isinstance(data, dict):
                continue
            score = data.get("baseScore")
            if isinstance(score, int | float) and 0.0 <= score <= 10.0:
                return float(score), clean_text(data.get("vectorString"))
    return None, None


def parse_cve(cve: dict[str, Any]) -> NvdData:
    """Normalize the ``cve`` object of an NVD response.

    Parameters:
        cve: The ``cve`` object of one item of ``vulnerabilities``.

    Returns:
        The normalized data.

    Raises:
        ValidationError: If the id or dates are malformed.
    """
    description = next(
        (
            d.get("value")
            for d in cve.get("descriptions", [])
            if isinstance(d, dict) and d.get("lang") == "en"
        ),
        None,
    )
    score, vector = _pick_cvss(cve.get("metrics"))
    urls = [
        url
        for r in cve.get("references", [])
        if isinstance(r, dict) and isinstance(url := r.get("url"), str) and url.startswith("http")
    ]
    return NvdData.model_validate(
        {
            "cve_id": cve.get("id"),
            "description": clean_text(description),
            "cvss_score": score,
            "cvss_vector": vector,
            "severity": severity_from_cvss(score),
            "published_at": cve.get("published"),
            "modified_at": cve.get("lastModified"),
            "references": [clean_text(u) for u in urls[:MAX_REFERENCES] if clean_text(u)],
        }
    )


class NvdClient:
    """Rate-limited client that fetches CVEs from NVD one at a time."""

    def __init__(
        self,
        client: httpx.Client,
        api_key: str | None = None,
        *,
        url: str = NVD_URL,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Create the client.

        Parameters:
            client: HTTP client.
            api_key: NVD API key. Optional; without it requests are ~10x slower.
                It is sent only as a header and never logged.
            url: API URL (overridable for tests).
            sleep: Function used to wait; injectable for tests.
            clock: Monotonic clock; injectable for tests.
        """
        self._client = client
        self._headers = {"apiKey": api_key} if api_key else {}
        self._url = url
        self._interval = INTERVAL_WITH_KEY if api_key else INTERVAL_WITHOUT_KEY
        self._sleep = sleep
        self._clock = clock
        self._last_request: float | None = None
        self.has_key = bool(api_key)

    def fetch(self, cve_id: str) -> NvdData | None:
        """Fetch and normalize one CVE, respecting the rate limit.

        Parameters:
            cve_id: A validated CVE id.

        Returns:
            The normalized data, or ``None`` if NVD does not know the CVE.

        Raises:
            FetchError: On request failure (``status_code`` 401/403 means the
                API key was rejected) or an unexpected payload.
        """
        if self._last_request is not None:
            wait = self._interval - (self._clock() - self._last_request)
            if wait > 0:
                self._sleep(wait)
        self._last_request = self._clock()
        payload = get_json(
            self._client, self._url, params={"cveId": cve_id}, headers=self._headers or None
        )
        items = payload.get("vulnerabilities") if isinstance(payload, dict) else None
        if not isinstance(items, list):
            raise FetchError("Unexpected NVD payload: missing 'vulnerabilities' list")
        if not items:
            return None
        try:
            return parse_cve(items[0]["cve"])
        except (ValidationError, KeyError, TypeError) as exc:
            raise FetchError(f"Invalid NVD record for {cve_id}") from exc
