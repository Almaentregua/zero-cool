"""Add EPSS scores to KEV vulnerabilities."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from zero_cool_api.models import Advisory, AdvisoryCve, Vulnerability
from zero_cool_api.sources.epss import EpssScore


def kev_cve_ids(session: Session) -> list[str]:
    """Return the ids of every vulnerability flagged as KEV.

    Parameters:
        session: Open session.

    Returns:
        CVE ids in alphabetical order.
    """
    query = select(Vulnerability.cve_id).where(Vulnerability.is_kev.is_(True))
    return list(session.scalars(query.order_by(Vulnerability.cve_id)))


def apply_epss(session: Session, scores: dict[str, EpssScore]) -> tuple[int, int]:
    """Store EPSS scores on the matching KEV vulnerabilities.

    EPSS changes daily, so existing values are always overwritten. A CVE that
    EPSS does not know keeps whatever it had (usually "not available").

    Parameters:
        session: Open session; committed once at the end.
        scores: Scores keyed by CVE id.

    Returns:
        ``(updated, missing)``: rows updated and KEV rows with no EPSS score.
    """
    updated = missing = 0
    for cve_id in kev_cve_ids(session):
        score = scores.get(cve_id)
        if score is None:
            missing += 1
            continue
        vuln = session.get(Vulnerability, cve_id)
        if vuln is None:  # pragma: no cover - the id was just read from this table
            continue
        vuln.epss_score = score.score
        vuln.epss_percentile = score.percentile
        updated += 1
    session.commit()
    return updated, missing


def all_cve_ids(session: Session) -> list[str]:
    """Return every CVE id that needs an EPSS score: KEV ones and those of advisories.

    Parameters:
        session: Open session.

    Returns:
        Distinct CVE ids in alphabetical order.
    """
    advisory_ids = set(session.scalars(select(AdvisoryCve.cve_id).distinct()))
    return sorted(set(kev_cve_ids(session)) | advisory_ids)


def apply_epss_to_advisories(session: Session, scores: dict[str, EpssScore]) -> tuple[int, int]:
    """Store EPSS on advisories: the highest score among their CVEs.

    The percentile is the one of the CVE with that highest score. An advisory whose
    CVEs have no score (or that has no CVE) keeps what it had, usually "not available".

    Parameters:
        session: Open session; committed once at the end.
        scores: Scores keyed by CVE id.

    Returns:
        ``(updated, without_score)``: advisories updated, and advisories with a CVE
        but no score.
    """
    updated = without_score = 0
    advisories = session.scalars(select(Advisory).join(AdvisoryCve).distinct())
    for advisory in advisories:
        found = [scores[c.cve_id] for c in advisory.cves if c.cve_id in scores]
        if not found:
            without_score += 1
            continue
        best = max(found, key=lambda s: s.score)
        advisory.epss_score = best.score
        advisory.epss_percentile = best.percentile
        updated += 1
    session.commit()
    return updated, without_score
