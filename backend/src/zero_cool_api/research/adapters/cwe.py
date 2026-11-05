"""MITRE CWE as a research source: what the weaknesses named in the CVE record mean."""

from zero_cool_api.research.base import Fetched
from zero_cool_api.sources.cve_org import CveOrgClient
from zero_cool_api.sources.cwe import CweClient

CWE_PAGE_URL = "https://cwe.mitre.org/data/definitions/{number}.html"
MAX_CWES = 10


class CweSource:
    """Official MITRE definition of each CWE that the CNA or CISA lists for the CVE.

    The CWE ids come from the CVE record; each entry says who listed it (``cna`` and/or
    ``cisa``) so the origin of the link stays visible. A CVE with no CWE is "no data".
    """

    id = "cwe"
    name = "MITRE CWE"
    cache_ttl_seconds = 24 * 3600

    def __init__(self, records: CveOrgClient, cwes: CweClient) -> None:
        """Create the source.

        Parameters:
            records: CVE record client (shared with the CVE.org source).
            cwes: CWE catalog client.
        """
        self._records = records
        self._cwes = cwes

    def fetch(self, cve_id: str) -> Fetched:
        """Look up the CWE entries referenced by a CVE.

        Parameters:
            cve_id: A validated CVE id.

        Returns:
            One entry per CWE (at most 10) with who listed it, or no data.

        Raises:
            FetchError: If CVE.org or the CWE API cannot be reached.
        """
        record = self._records.fetch(cve_id)
        if record is None:
            return Fetched(message="CVE.org has no record of this CVE id, so no CWE is known")
        listed_by: dict[str, list[str]] = {}
        for who, cwes in (
            ("cna", record.cna.cwes),
            ("cisa", record.cisa.cwes if record.cisa else []),
        ):
            for cwe in cwes:
                listed_by.setdefault(cwe.id, []).append(who)
        if not listed_by:
            return Fetched(message="The CVE record lists no CWE (neither the CNA nor CISA)")
        entries = []
        for cwe_id, authors in list(listed_by.items())[:MAX_CWES]:
            entry = self._cwes.fetch(cwe_id)
            item: dict[str, object] = {
                "id": cwe_id,
                "listed_by": authors,
                "url": CWE_PAGE_URL.format(number=cwe_id.removeprefix("CWE-")),
            }
            if entry is not None:
                item.update(entry.model_dump(mode="json", exclude={"id"}))
            else:
                item["name"] = None  # MITRE has no weakness or category with this id
            entries.append(item)
        return Fetched(origin_url="https://cwe.mitre.org/", data={"cwes": entries})
