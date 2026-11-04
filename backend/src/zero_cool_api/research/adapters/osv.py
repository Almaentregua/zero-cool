"""Package advisories (OSV / GitHub Advisory Database) as a research source."""

from collections.abc import Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from zero_cool_api.http import FetchError
from zero_cool_api.models import Advisory, AdvisoryCve
from zero_cool_api.research.base import Fetched

OSV_VULN_URL = "https://osv.dev/vulnerability/{id}"
MAX_ADVISORIES = 50
MAX_PACKAGES = 50


class OsvSource:
    """Advisories for Maven and npm packages that mention the CVE.

    Answered from the locally ingested OSV data, so it only covers the ecosystems in
    ``technologies.yaml``; the "no data" message says so.
    """

    id = "osv"
    name = "OSV / GitHub Advisories"
    cache_ttl_seconds = 300

    def __init__(self, session_factory: Callable[[], Session]) -> None:
        """Create the source.

        Parameters:
            session_factory: Returns a new database session (closed by the source).
        """
        self._session_factory = session_factory

    def fetch(self, cve_id: str) -> Fetched:
        """List the advisories that include a CVE.

        Parameters:
            cve_id: A validated CVE id.

        Returns:
            Each advisory with its severity and affected packages (versions untouched).

        Raises:
            FetchError: If no advisory has been ingested yet.
        """
        url = OSV_VULN_URL.format(id=cve_id)
        with self._session_factory() as session:
            advisories = list(
                session.scalars(
                    select(Advisory)
                    .join(AdvisoryCve, AdvisoryCve.advisory_id == Advisory.id)
                    .where(AdvisoryCve.cve_id == cve_id)
                    .order_by(Advisory.id)
                    .limit(MAX_ADVISORIES)
                )
            )
            if not advisories:
                if session.scalars(select(Advisory.id).limit(1)).first() is None:
                    raise FetchError("No package advisories have been ingested yet")
                return Fetched(
                    origin_url=url,
                    message="No advisory for Maven or npm packages in the local database",
                )
            items = [
                {
                    "id": a.id,
                    "summary": a.summary,
                    "severity": a.severity,
                    "cvss_vector": a.cvss_vector,
                    "github_reviewed": a.github_reviewed,
                    "published_at": a.published_at.isoformat() if a.published_at else None,
                    "url": OSV_VULN_URL.format(id=a.id),
                    "packages": [
                        {
                            "ecosystem": p.ecosystem,
                            "name": p.name,
                            "fixed_versions": p.fixed_versions,
                        }
                        for p in a.packages[:MAX_PACKAGES]
                    ],
                }
                for a in advisories
            ]
        return Fetched(origin_url=url, data={"advisories": items})
