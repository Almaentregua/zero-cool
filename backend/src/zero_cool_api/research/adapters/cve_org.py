"""CVE.org record and CISA Vulnrichment as research sources (one request, two blocks)."""

from zero_cool_api.research.base import Fetched
from zero_cool_api.sources.cve_org import CVE_SERVICES_URL, CveOrgClient

CVE_ORG_PAGE_URL = "https://www.cve.org/CVERecord?id={cve_id}"


class CveOrgSource:
    """The CVE record as published by the CNA that assigned the CVE.

    Includes the CNA's description, weaknesses, ratings, affected products and links.
    """

    id = "cve_org"
    name = "CVE.org (CNA record)"
    cache_ttl_seconds = 6 * 3600

    def __init__(self, client: CveOrgClient) -> None:
        """Create the source.

        Parameters:
            client: Shared CVE record client.
        """
        self._client = client

    def fetch(self, cve_id: str) -> Fetched:
        """Fetch the CNA part of the record.

        Parameters:
            cve_id: A validated CVE id.

        Returns:
            The CNA data, or no data if the CVE id does not exist.

        Raises:
            FetchError: If the CVE Services API cannot be reached.
        """
        url = CVE_ORG_PAGE_URL.format(cve_id=cve_id)
        record = self._client.fetch(cve_id)
        if record is None:
            return Fetched(origin_url=url, message="CVE.org has no record of this CVE id")
        return Fetched(origin_url=url, data=record.cna.model_dump(mode="json"))


class VulnrichmentSource:
    """CISA's enrichment of the record (Vulnrichment): SSVC, CVSS and CWE added by CISA.

    Kept apart from the CNA block: it is CISA's assessment, not the CNA's.
    """

    id = "vulnrichment"
    name = "CISA Vulnrichment"
    cache_ttl_seconds = 6 * 3600

    def __init__(self, client: CveOrgClient) -> None:
        """Create the source.

        Parameters:
            client: Shared CVE record client.
        """
        self._client = client

    def fetch(self, cve_id: str) -> Fetched:
        """Fetch CISA's part of the record.

        Parameters:
            cve_id: A validated CVE id.

        Returns:
            CISA's data, or no data if CISA has not enriched this CVE.

        Raises:
            FetchError: If the CVE Services API cannot be reached.
        """
        url = CVE_SERVICES_URL.format(cve_id=cve_id)
        record = self._client.fetch(cve_id)
        if record is None:
            return Fetched(origin_url=url, message="CVE.org has no record of this CVE id")
        if record.cisa is None:
            return Fetched(
                origin_url=url, message="CISA has not enriched this CVE (no Vulnrichment)"
            )
        return Fetched(origin_url=url, data=record.cisa.model_dump(mode="json"))
