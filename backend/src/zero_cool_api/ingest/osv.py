"""Store OSV advisories in the database."""

import logging
from collections.abc import Iterable
from dataclasses import dataclass

from sqlalchemy.orm import Session

from zero_cool_api.models import (
    Advisory,
    AdvisoryCve,
    AdvisoryPackage,
    AdvisoryReference,
)
from zero_cool_api.sources.osv import OsvAdvisory

logger = logging.getLogger(__name__)
COMMIT_EVERY = 500


@dataclass
class AdvisoryResult:
    """Counts of an advisory ingestion."""

    created: int = 0
    updated: int = 0
    unchanged: int = 0
    removed: int = 0


def _fill(advisory: Advisory, data: OsvAdvisory) -> None:
    """Copy source fields and replace the child rows. EPSS fields are not touched."""
    advisory.summary = data.summary
    advisory.details = data.details
    advisory.severity = data.severity
    advisory.cvss_vector = data.cvss_vector
    advisory.published_at = data.published_at
    advisory.modified_at = data.modified_at
    advisory.github_reviewed = data.github_reviewed
    advisory.cves = [AdvisoryCve(cve_id=c) for c in data.cve_ids]
    advisory.packages = [
        AdvisoryPackage(
            ecosystem=p.ecosystem,
            name=p.name,
            ranges_json=p.ranges_json,
            fixed_versions=p.fixed_versions,
        )
        for p in data.packages
    ]
    advisory.references = [AdvisoryReference(url=u) for u in data.references]


def upsert_advisories(session: Session, advisories: Iterable[OsvAdvisory]) -> AdvisoryResult:
    """Insert, update or remove advisories.

    - New advisories are created; existing ones are rewritten only when their
      ``modified_at`` changed, which keeps repeated runs fast.
    - Withdrawn advisories are deleted if present and never created.
    - EPSS values already stored on an advisory are preserved.

    Parameters:
        session: Open session; committed every 500 records and at the end.
        advisories: Normalized advisories. The same id may appear more than once
            (for example in the Maven and npm dumps); later copies are no-ops.

    Returns:
        Counts of what happened.
    """
    result = AdvisoryResult()
    for count, data in enumerate(advisories, start=1):
        existing = session.get(Advisory, data.id)
        if data.withdrawn:
            if existing is not None:
                session.delete(existing)
                result.removed += 1
        elif existing is None:
            advisory = Advisory(id=data.id)
            _fill(advisory, data)
            session.add(advisory)
            result.created += 1
        elif existing.modified_at == data.modified_at and existing.modified_at is not None:
            result.unchanged += 1
        else:
            _fill(existing, data)
            result.updated += 1
        if count % COMMIT_EVERY == 0:
            session.commit()
    session.commit()
    return result
