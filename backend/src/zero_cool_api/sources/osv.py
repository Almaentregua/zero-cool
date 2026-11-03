"""OSV.dev source: read the GitHub advisories (``GHSA-*``) from the ecosystem dumps.

OSV publishes one ``all.zip`` per ecosystem. For Maven and npm its vulnerability
records are GitHub's advisories in OSV format (see ADR 0003). Malicious-package
reports (``MAL-*``) and withdrawn advisories are not imported.
"""

import json
import logging
import re
import zipfile
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from pydantic import BaseModel, field_validator

from zero_cool_api.http import download_if_changed
from zero_cool_api.sources.kev import CVE_RE, clean_text

OSV_DUMP_URL = "https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"
ECOSYSTEM_RE = re.compile(r"^[A-Za-z0-9._-]+$")
GHSA_RE = re.compile(r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$")
MAX_MEMBER_BYTES = 5_000_000
MAX_REFERENCES = 100
MAX_DETAILS_LENGTH = 20_000
SEVERITY_MAP = {
    "LOW": "LOW",
    "MODERATE": "MEDIUM",
    "MEDIUM": "MEDIUM",
    "HIGH": "HIGH",
    "CRITICAL": "CRITICAL",
}

logger = logging.getLogger(__name__)


class OsvPackage(BaseModel):
    """A package affected by an advisory."""

    ecosystem: str
    name: str
    ranges_json: str | None
    fixed_versions: str | None


class OsvAdvisory(BaseModel):
    """A validated, normalized advisory."""

    id: str
    withdrawn: bool
    summary: str | None
    details: str | None
    severity: str | None
    cvss_vector: str | None
    published_at: datetime | None
    modified_at: datetime | None
    github_reviewed: bool | None
    cve_ids: list[str]
    packages: list[OsvPackage]
    references: list[str]

    @field_validator("published_at", "modified_at")
    @classmethod
    def _naive_utc(cls, value: datetime | None) -> datetime | None:
        """Store UTC without tzinfo, like the NVD dates."""
        if value is not None and value.tzinfo is not None:
            return value.astimezone(UTC).replace(tzinfo=None)
        return value


def _vector(severity_list: Any) -> str | None:
    """Pick the CVSS vector (v3 preferred over v4) from OSV's ``severity`` list."""
    if not isinstance(severity_list, list):
        return None
    vectors = {
        s.get("type"): s.get("score")
        for s in severity_list
        if isinstance(s, dict) and isinstance(s.get("score"), str)
    }
    for kind in ("CVSS_V3", "CVSS_V4"):
        score = vectors.get(kind)
        if score and score.startswith("CVSS:"):
            return clean_text(score)
    return None


def _packages(affected: Any, ecosystems: set[str]) -> list[OsvPackage]:
    """Merge the ``affected`` entries per package, keeping only wanted ecosystems."""
    merged: dict[tuple[str, str], list[Any]] = {}
    if not isinstance(affected, list):
        return []
    for entry in affected:
        package = entry.get("package") if isinstance(entry, dict) else None
        if not isinstance(package, dict):
            continue
        ecosystem, name = package.get("ecosystem"), clean_text(package.get("name"))
        if ecosystem not in ecosystems or not name:
            continue
        ranges = entry.get("ranges")
        merged.setdefault((ecosystem, name), []).extend(ranges if isinstance(ranges, list) else [])
    result = []
    for (ecosystem, name), ranges in merged.items():
        fixed = sorted(
            {
                str(event["fixed"])
                for r in ranges
                if isinstance(r, dict)
                for event in r.get("events", [])
                if isinstance(event, dict) and "fixed" in event
            }
        )
        result.append(
            OsvPackage(
                ecosystem=ecosystem,
                name=name,
                ranges_json=json.dumps(ranges, sort_keys=True) if ranges else None,
                fixed_versions=", ".join(fixed) or None,
            )
        )
    return result


def parse_record(raw: dict[str, Any], ecosystems: set[str]) -> OsvAdvisory | None:
    """Validate and normalize one OSV record.

    Parameters:
        raw: Decoded JSON of one OSV record.
        ecosystems: Ecosystems to keep (from ``technologies.yaml``).

    Returns:
        The advisory, or ``None`` if it is not a GitHub advisory or affects none of
        the wanted ecosystems. Withdrawn advisories are returned with
        ``withdrawn=True`` so the caller can remove them.

    Raises:
        ValueError: If the record is malformed (including an invalid id).
    """
    advisory_id = raw.get("id")
    if not isinstance(advisory_id, str) or not GHSA_RE.fullmatch(advisory_id):
        raise ValueError("not a valid GHSA id")
    packages = _packages(raw.get("affected"), ecosystems)
    if not packages:
        return None
    database = raw.get("database_specific")
    database = database if isinstance(database, dict) else {}
    raw_aliases = raw.get("aliases")
    aliases = raw_aliases if isinstance(raw_aliases, list) else []
    cves = sorted({a for a in aliases if isinstance(a, str) and CVE_RE.fullmatch(a)})
    raw_references = raw.get("references")
    urls: list[str] = []
    for ref in raw_references if isinstance(raw_references, list) else []:
        url = ref.get("url") if isinstance(ref, dict) else None
        if isinstance(url, str) and url.startswith(("http://", "https://")):
            cleaned = clean_text(url)
            if cleaned and cleaned not in urls:
                urls.append(cleaned)
    reviewed = database.get("github_reviewed")
    severity = database.get("severity")
    return OsvAdvisory(
        id=advisory_id,
        withdrawn=bool(raw.get("withdrawn")),
        summary=clean_text(raw.get("summary")),
        details=clean_text(raw.get("details"), MAX_DETAILS_LENGTH),
        severity=SEVERITY_MAP.get(severity.upper()) if isinstance(severity, str) else None,
        cvss_vector=_vector(raw.get("severity")),
        published_at=raw.get("published"),
        modified_at=raw.get("modified"),
        github_reviewed=reviewed if isinstance(reviewed, bool) else None,
        cve_ids=cves,
        packages=packages,
        references=urls[:MAX_REFERENCES],
    )


def iter_zip_records(zip_path: Path) -> Iterator[dict[str, Any]]:
    """Yield the decoded ``GHSA-*`` records of an OSV dump, without extracting it.

    Members are read one by one in memory. Names with a path, other kinds of records
    (such as ``MAL-*``), members larger than 5 MB and invalid JSON are skipped.

    Parameters:
        zip_path: A downloaded ``all.zip``.

    Yields:
        One decoded JSON object per valid member.

    Raises:
        zipfile.BadZipFile: If the file is not a valid zip.
    """
    skipped = 0
    with zipfile.ZipFile(zip_path) as archive:
        for info in archive.infolist():
            name = info.filename
            if not name.startswith("GHSA-") or "/" in name or not name.endswith(".json"):
                continue
            if info.file_size > MAX_MEMBER_BYTES:
                skipped += 1
                continue
            try:
                with archive.open(info) as member:
                    data = member.read(MAX_MEMBER_BYTES + 1)
                if len(data) > MAX_MEMBER_BYTES:
                    skipped += 1
                    continue
                record = json.loads(data)
            except (ValueError, zipfile.BadZipFile):
                skipped += 1
                continue
            if isinstance(record, dict):
                yield record
            else:
                skipped += 1
    if skipped:
        logger.warning("Skipped %d unreadable or oversized OSV records", skipped)


def iter_advisories(zip_path: Path, ecosystems: set[str]) -> Iterator[OsvAdvisory]:
    """Yield the valid advisories of a dump, skipping invalid ones.

    A record that fails validation is skipped (and counted in the log) without
    stopping the rest of the dump.

    Parameters:
        zip_path: A downloaded ``all.zip``.
        ecosystems: Ecosystems to keep.

    Yields:
        Normalized advisories, including withdrawn ones (flagged).

    Raises:
        zipfile.BadZipFile: If the file is not a valid zip.
    """
    skipped = 0
    for raw in iter_zip_records(zip_path):
        try:
            advisory = parse_record(raw, ecosystems)
        except ValueError:  # pydantic's ValidationError is a ValueError
            skipped += 1
            continue
        if advisory is not None:
            yield advisory
    if skipped:
        logger.warning("Skipped %d invalid OSV records", skipped)


def download_dump(
    client: httpx.Client, ecosystem: str, cache_dir: Path, *, url_template: str = OSV_DUMP_URL
) -> tuple[Path, bool]:
    """Download an ecosystem dump into the cache, unless it has not changed.

    Parameters:
        client: HTTP client.
        ecosystem: OSV ecosystem name (letters, digits, ``.``, ``_`` and ``-`` only).
        cache_dir: Directory for cached dumps.
        url_template: URL with an ``{ecosystem}`` placeholder (overridable for tests).

    Returns:
        ``(path of the zip, whether it was downloaded now)``.

    Raises:
        ValueError: If the ecosystem name has unexpected characters.
        FetchError: If the download fails.
    """
    if not ECOSYSTEM_RE.fullmatch(ecosystem):
        raise ValueError(f"Invalid ecosystem name: {ecosystem[:30]!r}")
    path = cache_dir / f"osv-{ecosystem}.zip"
    changed = download_if_changed(client, url_template.format(ecosystem=ecosystem), path)
    return path, changed
