"""CISA KEV as a research source (answered from the locally ingested catalog)."""

from collections.abc import Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from zero_cool_api.http import FetchError
from zero_cool_api.models import Vulnerability
from zero_cool_api.research.base import Fetched

KEV_PAGE_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"


class KevSource:
    """Tells whether a CVE is in CISA's Known Exploited Vulnerabilities catalog.

    "Not in KEV" is a real answer (``in_kev: false``), not missing data. It is only
    trustworthy when the catalog has been ingested, so an empty catalog is an error.
    """

    id = "kev"
    name = "CISA KEV"
    cache_ttl_seconds = 300  # local database: cheap, and ingestion may change it

    def __init__(self, session_factory: Callable[[], Session]) -> None:
        """Create the source.

        Parameters:
            session_factory: Returns a new database session (closed by the source).
        """
        self._session_factory = session_factory

    def fetch(self, cve_id: str) -> Fetched:
        """Look up a CVE in the ingested KEV catalog.

        Parameters:
            cve_id: A validated CVE id.

        Returns:
            ``in_kev`` plus the KEV fields when it is listed.

        Raises:
            FetchError: If the KEV catalog has not been ingested yet.
        """
        with self._session_factory() as session:
            vuln = session.get(Vulnerability, cve_id)
            if vuln is not None and vuln.is_kev:
                return Fetched(
                    origin_url=KEV_PAGE_URL,
                    data={
                        "in_kev": True,
                        "title": vuln.title,
                        "vendor": vuln.vendor,
                        "product": vuln.product,
                        "date_added": vuln.date_added.isoformat() if vuln.date_added else None,
                        "due_date": vuln.kev_due_date.isoformat() if vuln.kev_due_date else None,
                        "ransomware_use": vuln.ransomware_use,  # None = unknown
                    },
                )
            any_kev = session.scalars(
                select(Vulnerability.cve_id).where(Vulnerability.is_kev.is_(True)).limit(1)
            ).first()
        if any_kev is None:
            raise FetchError("The KEV catalog has not been ingested yet")
        return Fetched(origin_url=KEV_PAGE_URL, data={"in_kev": False})
