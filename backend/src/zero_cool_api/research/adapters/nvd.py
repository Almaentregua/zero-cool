"""NVD as a research source, queried on demand for any CVE (not only KEV ones)."""

import threading

from zero_cool_api.research.base import Fetched
from zero_cool_api.sources.nvd import NvdClient

NVD_DETAIL_URL = "https://nvd.nist.gov/vuln/detail/{cve_id}"


class NvdSource:
    """Official CVE detail from NVD: description, CVSS, dates and references."""

    id = "nvd"
    name = "NVD (NIST)"
    cache_ttl_seconds = 24 * 3600

    def __init__(self, client: NvdClient) -> None:
        """Create the source.

        Parameters:
            client: NVD client. It enforces the rate limit and is not thread safe, so
                calls are serialized with a lock.
        """
        self._client = client
        self._lock = threading.Lock()

    def fetch(self, cve_id: str) -> Fetched:
        """Fetch one CVE from NVD.

        Parameters:
            cve_id: A validated CVE id.

        Returns:
            The normalized NVD data, or no data if NVD does not know the CVE.

        Raises:
            FetchError: If NVD cannot be reached or rejects the request.
        """
        with self._lock:
            nvd = self._client.fetch(cve_id)
        url = NVD_DETAIL_URL.format(cve_id=cve_id)
        if nvd is None:
            return Fetched(origin_url=url, message="NVD has no record of this CVE")
        return Fetched(origin_url=url, data=nvd.model_dump(mode="json", exclude={"cve_id"}))
