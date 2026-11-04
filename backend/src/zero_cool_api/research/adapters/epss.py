"""EPSS (FIRST) as a research source."""

import httpx

from zero_cool_api.research.base import Fetched
from zero_cool_api.sources.epss import EPSS_URL, fetch_epss


class EpssSource:
    """Probability that a CVE will be exploited in the next 30 days."""

    id = "epss"
    name = "EPSS (FIRST)"
    cache_ttl_seconds = 3600  # scores change once a day

    def __init__(self, client: httpx.Client) -> None:
        """Create the source.

        Parameters:
            client: HTTP client.
        """
        self._client = client

    def fetch(self, cve_id: str) -> Fetched:
        """Fetch the EPSS score of one CVE.

        Parameters:
            cve_id: A validated CVE id.

        Returns:
            ``score`` and ``percentile`` (both 0 to 1), or no data if EPSS has no score.

        Raises:
            FetchError: If FIRST cannot be reached or answers with an unexpected payload.
        """
        url = f"{EPSS_URL}?cve={cve_id}"
        score = fetch_epss(self._client, [cve_id]).get(cve_id)
        if score is None:
            return Fetched(origin_url=url, message="EPSS has no score for this CVE")
        return Fetched(origin_url=url, data={"score": score.score, "percentile": score.percentile})
