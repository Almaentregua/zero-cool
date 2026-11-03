"""Add EPSS scores to KEV vulnerabilities."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from zero_cool_api.models import Vulnerability
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
