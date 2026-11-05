"""MITRE CWE source: official name and description of a weakness type.

Uses the CWE REST API (``https://cwe-api.mitre.org/api/v1``). ``/cwe/{id}`` only says what
kind of entry an id is; the details come from ``/cwe/weakness/{id}`` or
``/cwe/category/{id}``. Views are not weaknesses and are reported as having no data.
"""

import logging
import threading
import time
from collections.abc import Callable
from typing import Any

import httpx
from pydantic import BaseModel

from zero_cool_api.http import FetchError, get_json
from zero_cool_api.sources.kev import clean_text

CWE_API_URL = "https://cwe-api.mitre.org/api/v1/cwe"
WEAKNESS_TYPES = {"base_weakness", "class_weakness", "variant_weakness", "compound_element"}
MAX_CONSEQUENCES = 10

logger = logging.getLogger(__name__)


class CweEntry(BaseModel):
    """Normalized CWE entry (a weakness or a category)."""

    id: str
    kind: str  # "weakness" or "category"
    name: str | None
    abstraction: str | None = None  # Class / Base / Variant ... (weaknesses only)
    status: str | None
    description: str | None
    likelihood_of_exploit: str | None = None
    consequences: list[dict[str, Any]] = []


def _text(value: Any) -> str | None:
    return clean_text(value) if isinstance(value, str) else None


def _first(payload: Any, key: str) -> dict[str, Any]:
    """Return the first object of ``payload[key]`` or raise ``FetchError``."""
    items = payload.get(key) if isinstance(payload, dict) else None
    if not isinstance(items, list) or not items or not isinstance(items[0], dict):
        raise FetchError(f"Unexpected CWE payload: missing '{key}'")
    return items[0]


def parse_weakness(payload: Any) -> CweEntry:
    """Normalize a ``/cwe/weakness/{id}`` response.

    Parameters:
        payload: Decoded JSON.

    Returns:
        The entry. Only fields shown in a report are kept.

    Raises:
        FetchError: If the payload has no weakness.
    """
    item = _first(payload, "Weaknesses")
    consequences: list[dict[str, Any]] = []
    raw = item.get("CommonConsequences")
    for c in (raw if isinstance(raw, list) else [])[:MAX_CONSEQUENCES]:
        if isinstance(c, dict):
            consequences.append(
                {
                    "scope": [t for t in map(_text, c.get("Scope") or []) if t],
                    "impact": [t for t in map(_text, c.get("Impact") or []) if t],
                    "note": _text(c.get("Note")),
                }
            )
    return CweEntry(
        id=f"CWE-{_text(item.get('ID'))}",
        kind="weakness",
        name=_text(item.get("Name")),
        abstraction=_text(item.get("Abstraction")),
        status=_text(item.get("Status")),
        description=_text(item.get("Description")),
        likelihood_of_exploit=_text(item.get("LikelihoodOfExploit")),
        consequences=consequences,
    )


def parse_category(payload: Any) -> CweEntry:
    """Normalize a ``/cwe/category/{id}`` response.

    Parameters:
        payload: Decoded JSON.

    Returns:
        The entry; its text comes from the category's ``Summary``.

    Raises:
        FetchError: If the payload has no category.
    """
    item = _first(payload, "Categories")
    return CweEntry(
        id=f"CWE-{_text(item.get('ID'))}",
        kind="category",
        name=_text(item.get("Name")),
        status=_text(item.get("Status")),
        description=_text(item.get("Summary")),
    )


class CweClient:
    """Fetches CWE entries, remembering each one (the catalog changes a few times a year)."""

    def __init__(
        self,
        client: httpx.Client,
        *,
        url: str = CWE_API_URL,
        memo_seconds: float = 24 * 3600,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Create the client.

        Parameters:
            client: HTTP client.
            url: API base URL (overridable for tests).
            memo_seconds: How long a fetched entry is reused.
            clock: Monotonic clock; injectable for tests.
        """
        self._client = client
        self._url = url
        self._memo_seconds = memo_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._memo: dict[str, tuple[float, CweEntry | None]] = {}

    def fetch(self, cwe_id: str) -> CweEntry | None:
        """Fetch one CWE entry.

        Parameters:
            cwe_id: An id such as ``CWE-502`` (validated by the caller).

        Returns:
            The entry, or ``None`` if the id does not exist or is a view.

        Raises:
            FetchError: On request failure or an unexpected payload.
        """
        number = cwe_id.removeprefix("CWE-")
        with self._lock:
            hit = self._memo.get(cwe_id)
            if hit is not None and self._clock() < hit[0]:
                return hit[1]
            entry = self._load(number)
            self._memo[cwe_id] = (self._clock() + self._memo_seconds, entry)
            return entry

    def _load(self, number: str) -> CweEntry | None:
        try:
            kinds = get_json(self._client, f"{self._url}/{number}")
        except FetchError as exc:
            if exc.status_code == 404:
                return None
            raise
        kind = kinds[0].get("Type") if isinstance(kinds, list) and kinds else None
        if kind in WEAKNESS_TYPES:
            return parse_weakness(get_json(self._client, f"{self._url}/weakness/{number}"))
        if kind == "category":
            return parse_category(get_json(self._client, f"{self._url}/category/{number}"))
        return None
