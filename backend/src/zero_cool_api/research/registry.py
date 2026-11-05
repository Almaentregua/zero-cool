"""The list of research sources the app uses."""

import os
from collections.abc import Callable

import httpx
from sqlalchemy.orm import Session

from zero_cool_api.research.adapters.cve_org import CveOrgSource, VulnrichmentSource
from zero_cool_api.research.adapters.cwe import CweSource
from zero_cool_api.research.adapters.epss import EpssSource
from zero_cool_api.research.adapters.kev import KevSource
from zero_cool_api.research.adapters.nvd import NvdSource
from zero_cool_api.research.adapters.osv import OsvSource
from zero_cool_api.research.base import ResearchSource
from zero_cool_api.sources.cve_org import CveOrgClient
from zero_cool_api.sources.cwe import CweClient
from zero_cool_api.sources.nvd import NvdClient

HTTP_TIMEOUT_SECONDS = 10.0


def build_sources(
    session_factory: Callable[[], Session],
    client: httpx.Client | None = None,
    nvd_api_key: str | None = None,
) -> list[ResearchSource]:
    """Create every research source, in the order they appear in a report.

    Add new sources here; nothing else needs to change.

    Parameters:
        session_factory: Returns a new database session, for the sources backed by the
            local database.
        client: Shared HTTP client. Defaults to one with a short timeout.
        nvd_api_key: NVD API key. Defaults to the ``NVD_API_KEY`` environment variable.
            It is only sent as a header and never logged.

    Returns:
        The sources, newest additions last.
    """
    http = client or httpx.Client(timeout=HTTP_TIMEOUT_SECONDS, follow_redirects=True)
    key = nvd_api_key if nvd_api_key is not None else os.environ.get("NVD_API_KEY") or None
    cve_records = CveOrgClient(http)
    return [
        KevSource(session_factory),
        NvdSource(NvdClient(http, key)),
        EpssSource(http),
        OsvSource(session_factory),
        CveOrgSource(cve_records),
        VulnrichmentSource(cve_records),
        CweSource(cve_records, CweClient(http)),
    ]
