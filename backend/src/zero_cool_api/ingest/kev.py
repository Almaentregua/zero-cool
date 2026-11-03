"""Store the KEV catalog in the database."""

from sqlalchemy.orm import Session

from zero_cool_api.models import Vulnerability
from zero_cool_api.sources.kev import KevEntry


def upsert_kev(session: Session, entries: list[KevEntry]) -> tuple[int, int]:
    """Insert or update vulnerabilities from KEV entries.

    Only KEV-owned fields are written. Data from other sources (NVD, EPSS) on
    an existing row is preserved. KEV's short description is used only while no
    other description exists, so NVD's can later replace it.

    Parameters:
        session: Open session. The caller decides about committing; this
            function commits once at the end.
        entries: Normalized KEV entries.

    Returns:
        ``(created, updated)`` counts.
    """
    created = updated = 0
    for entry in entries:
        vuln = session.get(Vulnerability, entry.cve_id)
        if vuln is None:
            vuln = Vulnerability(cve_id=entry.cve_id)
            session.add(vuln)
            created += 1
        else:
            updated += 1
        vuln.is_kev = True
        vuln.vendor = entry.vendor
        vuln.product = entry.product
        vuln.title = entry.title
        vuln.date_added = entry.date_added
        vuln.kev_due_date = entry.due_date
        vuln.ransomware_use = entry.ransomware_use
        if vuln.description is None:
            vuln.description = entry.description
    session.commit()
    return created, updated
