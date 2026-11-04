"""Common types for research sources.

A research source answers one question: "what do you know about this CVE?". Each source
is a small class with the same interface, so the page, the reports and the runner never
depend on a source's own format (adding a source means adding one module).
"""

from datetime import datetime
from typing import Any, Literal, Protocol
from urllib.parse import urlparse

from pydantic import BaseModel, field_validator

from zero_cool_api.sources.kev import CVE_RE

Status = Literal["ok", "no_data", "error"]


def normalize_cve_id(raw: str) -> str:
    """Validate and normalize a CVE id typed by the user, before any external call.

    Parameters:
        raw: Text such as ``" cve-2021-44228 "``.

    Returns:
        The id in canonical form, e.g. ``CVE-2021-44228``.

    Raises:
        ValueError: If the text is not a valid CVE id.
    """
    cve_id = raw.strip().upper()
    if not CVE_RE.fullmatch(cve_id):
        raise ValueError("Invalid CVE id")
    return cve_id


class Fetched(BaseModel):
    """What a source returns for a CVE when the request itself worked.

    Attributes:
        data: Normalized data, or ``None`` when the source has nothing about the CVE.
        origin_url: Link to the place the data comes from (http/https only).
        message: Why there is no data, when ``data`` is ``None``.
    """

    data: dict[str, Any] | None = None
    origin_url: str | None = None
    message: str | None = None

    @field_validator("origin_url")
    @classmethod
    def _http_only(cls, value: str | None) -> str | None:
        # External links end up as <a href>: only http(s) is safe to keep.
        if value is not None and urlparse(value).scheme not in ("http", "https"):
            raise ValueError("origin_url must be http or https")
        return value


class SourceResult(BaseModel):
    """The outcome of asking one source about one CVE, as shown in a report.

    Every source consulted produces one of these, even when it had nothing to say or
    failed, so a report always states which sources were checked.
    """

    source: str
    source_name: str
    cve_id: str
    status: Status
    message: str | None = None
    origin_url: str | None = None
    retrieved_at: datetime
    data: dict[str, Any] | None = None


class ResearchSource(Protocol):
    """Interface every research source implements.

    Attributes:
        id: Stable identifier stored in reports, e.g. ``"nvd"``.
        name: Human-readable name shown in the report, e.g. ``"NVD (NIST)"``.
        cache_ttl_seconds: How long a result may be reused without asking the source again.
    """

    id: str
    name: str
    cache_ttl_seconds: int

    def fetch(self, cve_id: str) -> Fetched:
        """Ask the source about a CVE.

        Parameters:
            cve_id: A CVE id already validated by :func:`normalize_cve_id`.

        Returns:
            The normalized answer; ``data=None`` when the source has nothing.

        Raises:
            FetchError: If the source cannot be reached after retries.
        """
        ...
