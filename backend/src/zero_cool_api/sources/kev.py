"""CISA Known Exploited Vulnerabilities (KEV) source: fetch, validate, normalize."""

import logging
import re
from datetime import date
from typing import Any

import httpx
from pydantic import BaseModel, ValidationError, field_validator

from zero_cool_api.http import FetchError, get_json

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
MAX_TEXT_LENGTH = 5000

logger = logging.getLogger(__name__)


def clean_text(value: str | None) -> str | None:
    """Sanitize untrusted text: strip control characters and bound its length.

    HTML is not interpreted or removed here; the frontend must render it as
    plain text.

    Parameters:
        value: Raw text from an external source.

    Returns:
        The cleaned text, or ``None`` if the input is ``None`` or blank.
    """
    if value is None:
        return None
    cleaned = _CONTROL_CHARS.sub("", value).strip()
    return cleaned[:MAX_TEXT_LENGTH] or None


class KevEntry(BaseModel):
    """One validated entry of the KEV catalog, with the app's field names."""

    cve_id: str
    vendor: str | None
    product: str | None
    title: str | None
    description: str | None
    date_added: date
    due_date: date | None
    ransomware_use: bool | None  # None = value missing or not recognized

    @field_validator("cve_id")
    @classmethod
    def _valid_cve(cls, value: str) -> str:
        value = value.strip().upper()
        if not CVE_RE.fullmatch(value):
            raise ValueError(f"invalid CVE id: {value[:30]!r}")
        return value


def parse_entry(raw: dict[str, Any]) -> KevEntry:
    """Validate and normalize one raw KEV record.

    Parameters:
        raw: A record of the ``vulnerabilities`` array.

    Returns:
        The normalized entry.

    Raises:
        ValidationError: If the CVE id or the dates are invalid.
    """
    ransomware = raw.get("knownRansomwareCampaignUse")
    return KevEntry.model_validate(
        {
            "cve_id": str(raw.get("cveID", "")),
            "vendor": clean_text(raw.get("vendorProject")),
            "product": clean_text(raw.get("product")),
            "title": clean_text(raw.get("vulnerabilityName")),
            "description": clean_text(raw.get("shortDescription")),
            "date_added": raw.get("dateAdded"),
            "due_date": raw.get("dueDate") or None,
            "ransomware_use": {"Known": True, "Unknown": False}.get(str(ransomware)),
        }
    )


def parse_catalog(payload: Any) -> list[KevEntry]:
    """Normalize a whole KEV catalog, skipping invalid records.

    Parameters:
        payload: Decoded JSON of the KEV feed.

    Returns:
        The valid entries. Invalid records are logged (count only) and skipped,
        so one bad record does not block the rest.

    Raises:
        FetchError: If the payload does not look like a KEV catalog.
    """
    if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
        raise FetchError("Unexpected KEV payload: missing 'vulnerabilities' list")
    entries: list[KevEntry] = []
    skipped = 0
    for raw in payload["vulnerabilities"]:
        try:
            entries.append(parse_entry(raw))
        except (ValidationError, AttributeError, TypeError):
            skipped += 1
    if skipped:
        logger.warning("Skipped %d invalid KEV records", skipped)
    return entries


def fetch_kev(client: httpx.Client, url: str = KEV_URL) -> list[KevEntry]:
    """Download and normalize the KEV catalog.

    Parameters:
        client: HTTP client.
        url: Feed URL (overridable for tests).

    Returns:
        The valid catalog entries.

    Raises:
        FetchError: If the download fails or the payload is not a KEV catalog.
    """
    return parse_catalog(get_json(client, url))
