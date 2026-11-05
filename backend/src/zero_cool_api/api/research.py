"""Endpoint that investigates one CVE across every research source."""

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from zero_cool_api.api.deps import ResearchSourcesDep, ResultCacheDep
from zero_cool_api.research.base import SourceResult, Status
from zero_cool_api.research.runner import research

router = APIRouter(prefix="/api")

EXAMPLE = {
    "cve_id": "CVE-2021-44228",
    "generated_at": "2026-11-04T15:00:00Z",
    "sources": [
        {"source": "kev", "source_name": "CISA KEV", "status": "ok"},
        {"source": "osv", "source_name": "OSV / GitHub Advisories", "status": "no_data"},
        {"source": "nvd", "source_name": "NVD (NIST)", "status": "error"},
    ],
    "results": [
        {
            "source": "kev",
            "source_name": "CISA KEV",
            "cve_id": "CVE-2021-44228",
            "status": "ok",
            "message": None,
            "origin_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "retrieved_at": "2026-11-04T15:00:00Z",
            "data": {"in_kev": True, "date_added": "2021-12-10", "ransomware_use": True},
        },
        {
            "source": "osv",
            "source_name": "OSV / GitHub Advisories",
            "cve_id": "CVE-2021-44228",
            "status": "no_data",
            "message": "No advisory for Maven or npm packages in the local database",
            "origin_url": "https://osv.dev/vulnerability/CVE-2021-44228",
            "retrieved_at": "2026-11-04T15:00:00Z",
            "data": None,
        },
        {
            "source": "nvd",
            "source_name": "NVD (NIST)",
            "cve_id": "CVE-2021-44228",
            "status": "error",
            "message": "The source did not answer within 15 s",
            "origin_url": None,
            "retrieved_at": "2026-11-04T15:00:00Z",
            "data": None,
        },
    ],
}


class SourceStatus(BaseModel):
    """One line of the summary of consulted sources."""

    source: str = Field(description="Source id.", examples=["nvd"])
    source_name: str = Field(description="Name shown to the user.", examples=["NVD (NIST)"])
    status: Status = Field(description="`ok` (has data), `no_data` or `error`.")


class ResearchResponse(BaseModel):
    """Everything known about one CVE, one block per source."""

    cve_id: str = Field(description="Normalized CVE id.", examples=["CVE-2021-44228"])
    generated_at: datetime = Field(description="When this answer was assembled (UTC).")
    sources: list[SourceStatus] = Field(
        description="Every source that was consulted, including those with no data or an error."
    )
    results: list[SourceResult] = Field(
        description="One block per source, in report order. Values are never merged."
    )


@router.get(
    "/research/{cve_id}",
    summary="Investigate a CVE across all sources",
    description=(
        "Asks every research source about the CVE (KEV, NVD, EPSS, OSV advisories, CVE.org, "
        "CISA Vulnrichment, MITRE CWE) and returns one block per source, each with its origin "
        "link, retrieval time and status (`ok`, `no_data` or `error` with a reason). Works for "
        "any CVE, in KEV or not. One failing source does not fail the request. Results are "
        "cached per source; pass `refresh=true` to bypass the cache. Nothing is invented: a "
        "missing value is `null`. The id is case-insensitive; an invalid id returns 422 and "
        "no source is called."
    ),
    response_model=ResearchResponse,
    responses={
        200: {
            "description": "One block per source.",
            "content": {"application/json": {"example": EXAMPLE}},
        },
        422: {"description": "Invalid CVE id."},
    },
)
def investigate(
    cve_id: str,
    sources: ResearchSourcesDep,
    cache: ResultCacheDep,
    refresh: Annotated[bool, Query(description="Ignore cached results.")] = False,
) -> ResearchResponse:
    try:
        results = research(cve_id, sources, cache=cache, force=refresh)
    except ValueError as exc:
        raise HTTPException(422, "Invalid CVE id; expected format CVE-YYYY-NNNN") from exc
    return ResearchResponse(
        cve_id=results[0].cve_id if results else cve_id.strip().upper(),
        generated_at=datetime.now(UTC),
        sources=[
            SourceStatus(source=r.source, source_name=r.source_name, status=r.status)
            for r in results
        ],
        results=results,
    )
