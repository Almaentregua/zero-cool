"""Enrich KEV vulnerabilities with NVD data."""

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from zero_cool_api.http import FetchError
from zero_cool_api.models import Reference, Vulnerability
from zero_cool_api.sources.nvd import NvdClient, NvdData

logger = logging.getLogger(__name__)
COMMIT_EVERY = 25


class NvdAuthError(Exception):
    """Raised when NVD rejects the API key."""


@dataclass
class NvdResult:
    """Counts of an NVD enrichment run."""

    enriched: int = 0
    not_found: int = 0
    failed: int = 0
    skipped_recent: int = 0


def apply_nvd(vuln: Vulnerability, data: NvdData) -> None:
    """Copy NVD data onto a vulnerability (NVD owns description and CVSS).

    Parameters:
        vuln: The row to update.
        data: Normalized NVD data for the same CVE.
    """
    if data.description:
        vuln.description = data.description
    vuln.cvss_score = data.cvss_score
    vuln.cvss_vector = data.cvss_vector
    vuln.severity = data.severity
    vuln.published_at = data.published_at
    vuln.modified_at = data.modified_at
    vuln.references = [Reference(url=u) for u in dict.fromkeys(data.references)]


def enrich_from_nvd(
    session: Session,
    client: NvdClient,
    *,
    limit: int | None = None,
    force: bool = False,
    max_age_days: int = 7,
    progress: Callable[[int, int], None] | None = None,
    now: Callable[[], datetime] = lambda: datetime.now(UTC).replace(tzinfo=None),
) -> NvdResult:
    """Query NVD for KEV vulnerabilities and store the results.

    CVEs queried within ``max_age_days`` are skipped unless ``force`` is set, so
    re-running is cheap and an interrupted run resumes where it stopped.

    Parameters:
        session: Open session.
        client: NVD client.
        limit: Query at most this many CVEs (useful to try the pipeline).
        force: Ignore ``max_age_days``.
        max_age_days: Freshness window.
        progress: Optional callback ``(done, total)``.
        now: Clock, injectable for tests.

    Returns:
        Counts of what happened.

    Raises:
        NvdAuthError: If NVD rejects the API key (the run stops; work already
            done is kept).
    """
    result = NvdResult()
    query = select(Vulnerability).where(Vulnerability.is_kev.is_(True))
    if not force:
        cutoff = now() - timedelta(days=max_age_days)
        total_kev = len(session.scalars(query).all())
        query = query.where(
            or_(Vulnerability.nvd_fetched_at.is_(None), Vulnerability.nvd_fetched_at < cutoff)
        )
    pending = list(session.scalars(query.order_by(Vulnerability.cve_id)))
    if not force:
        result.skipped_recent = total_kev - len(pending)
    if limit is not None:
        pending = pending[:limit]

    for done, vuln in enumerate(pending, start=1):
        try:
            data = client.fetch(vuln.cve_id)
        except FetchError as exc:
            if exc.status_code in (401, 403):
                session.commit()
                raise NvdAuthError("NVD rejected the API key; check NVD_API_KEY") from exc
            logger.warning("NVD failed for %s: %s", vuln.cve_id, exc)
            result.failed += 1
            continue
        vuln.nvd_fetched_at = now()
        if data is None:
            result.not_found += 1
        else:
            apply_nvd(vuln, data)
            result.enriched += 1
        if done % COMMIT_EVERY == 0:
            session.commit()
        if progress:
            progress(done, len(pending))
    session.commit()
    return result
