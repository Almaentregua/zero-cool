"""CVE.org (CVE Program) source: fetch one CVE record and split it by who wrote what.

The CVE Services API returns the CNA's own record plus "ADP" containers added by other
organizations. CISA's container (``CISA-ADP``, the Vulnrichment project) carries CVSS,
SSVC and CWE data. The two are kept apart because they come from different authors.
"""

import logging
import re
import threading
import time
from collections.abc import Callable
from typing import Any

import httpx
from pydantic import BaseModel

from zero_cool_api.http import FetchError, get_json
from zero_cool_api.sources.kev import clean_text

CVE_SERVICES_URL = "https://cveawg.mitre.org/api/cve/{cve_id}"
CISA_ADP = "CISA-ADP"
MAX_REFERENCES = 50
MAX_AFFECTED = 50
MAX_VERSIONS = 20
CVSS_KEYS = ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0")
CWE_RE = re.compile(r"^CWE-\d{1,5}$")
SSVC_FIELDS = {
    "Exploitation": "exploitation",
    "Automatable": "automatable",
    "Technical Impact": "technical_impact",
}

logger = logging.getLogger(__name__)


class Cvss(BaseModel):
    """One CVSS rating exactly as the author published it."""

    version: str
    score: float
    vector: str | None
    severity: str | None


class Cwe(BaseModel):
    """A weakness type referenced by a record."""

    id: str
    description: str | None


class Ssvc(BaseModel):
    """CISA's SSVC decision points. A value is ``None`` when CISA did not publish it."""

    exploitation: str | None = None  # none / poc / active
    automatable: str | None = None  # yes / no
    technical_impact: str | None = None  # partial / total
    version: str | None = None
    timestamp: str | None = None


class Affected(BaseModel):
    """A vendor/product the CNA declares affected, with its version entries."""

    vendor: str | None
    product: str | None
    default_status: str | None
    versions: list[dict[str, str | None]]


class CnaData(BaseModel):
    """What the CNA (the organization that assigned the CVE) published."""

    state: str
    assigner: str | None
    published_at: str | None
    updated_at: str | None
    title: str | None
    description: str | None
    cwes: list[Cwe]
    cvss: list[Cvss]
    affected: list[Affected]
    references: list[str]


class CisaData(BaseModel):
    """What CISA added in its ADP container (Vulnrichment)."""

    cvss: list[Cvss]
    cwes: list[Cwe]
    ssvc: Ssvc | None


class CveRecord(BaseModel):
    """A parsed CVE record. ``cisa`` is ``None`` when CISA did not enrich it."""

    cna: CnaData
    cisa: CisaData | None


def _text(value: Any) -> str | None:
    return clean_text(value) if isinstance(value, str) else None


def _english(items: Any) -> str | None:
    """Return the first English text of a ``descriptions``-style list."""
    if not isinstance(items, list):
        return None
    for item in items:
        if isinstance(item, dict) and str(item.get("lang", "")).lower().startswith("en"):
            return _text(item.get("value"))
    return None


def _cvss(metrics: Any) -> list[Cvss]:
    """Collect the CVSS ratings of a ``metrics`` list, ignoring malformed ones."""
    found: list[Cvss] = []
    for metric in metrics if isinstance(metrics, list) else []:
        if not isinstance(metric, dict):
            continue
        for key in CVSS_KEYS:
            data = metric.get(key)
            if not isinstance(data, dict):
                continue
            score = data.get("baseScore")
            if isinstance(score, int | float) and 0.0 <= score <= 10.0:
                found.append(
                    Cvss(
                        version=key.removeprefix("cvssV").replace("_", "."),
                        score=float(score),
                        vector=_text(data.get("vectorString")),
                        severity=_text(data.get("baseSeverity")),
                    )
                )
    return found


def _cwes(problem_types: Any) -> list[Cwe]:
    """Collect the distinct CWE entries of a ``problemTypes`` list."""
    found: dict[str, Cwe] = {}
    for problem in problem_types if isinstance(problem_types, list) else []:
        for item in problem.get("descriptions", []) if isinstance(problem, dict) else []:
            cwe_id = item.get("cweId") if isinstance(item, dict) else None
            if isinstance(cwe_id, str) and CWE_RE.fullmatch(cwe_id):
                found.setdefault(cwe_id, Cwe(id=cwe_id, description=_text(item.get("description"))))
    return list(found.values())


def _ssvc(metrics: Any) -> Ssvc | None:
    """Extract the SSVC decision from a ``metrics`` list, if present."""
    for metric in metrics if isinstance(metrics, list) else []:
        other = metric.get("other") if isinstance(metric, dict) else None
        if not isinstance(other, dict) or other.get("type") != "ssvc":
            continue
        content = other.get("content")
        if not isinstance(content, dict):
            continue
        values: dict[str, Any] = {}
        for option in content.get("options", []):
            if isinstance(option, dict):
                for name, value in option.items():
                    if name in SSVC_FIELDS:
                        values[SSVC_FIELDS[name]] = _text(value)
        values["version"] = _text(content.get("version"))
        values["timestamp"] = _text(content.get("timestamp"))
        return Ssvc(**values)
    return None


def _affected(items: Any) -> list[Affected]:
    result: list[Affected] = []
    for item in (items if isinstance(items, list) else [])[:MAX_AFFECTED]:
        if not isinstance(item, dict):
            continue
        versions: list[dict[str, str | None]] = []
        for v in (
            item.get("versions", [])[:MAX_VERSIONS]
            if isinstance(item.get("versions"), list)
            else []
        ):
            if isinstance(v, dict):
                versions.append(
                    {
                        "version": _text(v.get("version")),
                        "status": _text(v.get("status")),
                        "less_than": _text(v.get("lessThan")),
                        "less_than_or_equal": _text(v.get("lessThanOrEqual")),
                    }
                )
        result.append(
            Affected(
                vendor=_text(item.get("vendor")),
                product=_text(item.get("product")),
                default_status=_text(item.get("defaultStatus")),
                versions=versions,
            )
        )
    return result


def parse_record(payload: Any) -> CveRecord:
    """Validate and normalize a CVE Services response.

    Parameters:
        payload: Decoded JSON of ``/api/cve/{id}``.

    Returns:
        The CNA data and, when present, CISA's enrichment.

    Raises:
        FetchError: If the payload does not look like a CVE record.
    """
    if not isinstance(payload, dict):
        raise FetchError("Unexpected CVE.org payload")
    meta = payload.get("cveMetadata")
    containers = payload.get("containers")
    if not isinstance(meta, dict) or not isinstance(containers, dict):
        raise FetchError("Unexpected CVE.org payload: missing metadata or containers")
    cna = containers.get("cna")
    cna = cna if isinstance(cna, dict) else {}
    refs = [
        url
        for r in cna.get("references", [])
        if isinstance(r, dict) and isinstance(url := r.get("url"), str) and url.startswith("http")
    ]
    # Rejected records have no description; the reason is the only text there is.
    description = _english(cna.get("descriptions")) or _english(cna.get("rejectedReasons"))
    cna_data = CnaData(
        state=_text(meta.get("state")) or "UNKNOWN",
        assigner=_text(meta.get("assignerShortName")),
        published_at=_text(meta.get("datePublished")),
        updated_at=_text(meta.get("dateUpdated")),
        title=_text(cna.get("title")),
        description=description,
        cwes=_cwes(cna.get("problemTypes")),
        cvss=_cvss(cna.get("metrics")),
        affected=_affected(cna.get("affected")),
        references=[u for u in (_text(r) for r in refs[:MAX_REFERENCES]) if u],
    )
    cisa: CisaData | None = None
    for adp in containers.get("adp", []) if isinstance(containers.get("adp"), list) else []:
        provider = adp.get("providerMetadata") if isinstance(adp, dict) else None
        if isinstance(provider, dict) and provider.get("shortName") == CISA_ADP:
            cisa = CisaData(
                cvss=_cvss(adp.get("metrics")),
                cwes=_cwes(adp.get("problemTypes")),
                ssvc=_ssvc(adp.get("metrics")),
            )
            break
    return CveRecord(cna=cna_data, cisa=cisa)


class CveOrgClient:
    """Fetches CVE records, remembering each for a short time.

    The CVE.org and Vulnrichment research sources read the same record; the memo makes
    them share one request when they run together.
    """

    def __init__(
        self,
        client: httpx.Client,
        *,
        url_template: str = CVE_SERVICES_URL,
        memo_seconds: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Create the client.

        Parameters:
            client: HTTP client.
            url_template: API URL with a ``{cve_id}`` placeholder (overridable for tests).
            memo_seconds: How long a fetched record is reused.
            clock: Monotonic clock; injectable for tests.
        """
        self._client = client
        self._url_template = url_template
        self._memo_seconds = memo_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._memo: dict[str, tuple[float, CveRecord | None]] = {}

    def fetch(self, cve_id: str) -> CveRecord | None:
        """Fetch and parse one CVE record.

        Parameters:
            cve_id: A validated CVE id.

        Returns:
            The record, or ``None`` if the CVE does not exist (HTTP 404).

        Raises:
            FetchError: On request failure or an unexpected payload.
        """
        with self._lock:
            hit = self._memo.get(cve_id)
            if hit is not None and self._clock() < hit[0]:
                return hit[1]
            try:
                payload = get_json(self._client, self._url_template.format(cve_id=cve_id))
            except FetchError as exc:
                if exc.status_code != 404:
                    raise
                record = None
            else:
                record = parse_record(payload)
            self._memo[cve_id] = (self._clock() + self._memo_seconds, record)
            return record
