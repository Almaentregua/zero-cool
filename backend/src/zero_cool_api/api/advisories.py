"""Endpoints for package advisories (GitHub advisories via OSV)."""

import json
from datetime import date
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from zero_cool_api.api.deps import SessionDep, TechnologiesDep
from zero_cool_api.api.schemas import (
    AdvisoryCveRef,
    AdvisoryDetail,
    AdvisoryPackage,
    AdvisoryPage,
    AdvisorySummary,
    PackageRef,
)
from zero_cool_api.models import Advisory, Vulnerability
from zero_cool_api.queries import (
    AdvisoryFilters,
    AdvisorySortField,
    SortOrder,
    search_advisories,
    technologies_for_ecosystems,
)
from zero_cool_api.sources.osv import GHSA_RE
from zero_cool_api.technologies import Technology

router = APIRouter(prefix="/api")

Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _summary(advisory: Advisory, technologies: list[Technology]) -> AdvisorySummary:
    return AdvisorySummary(
        id=advisory.id,
        summary=advisory.summary,
        severity=advisory.severity,
        epss_score=advisory.epss_score,
        epss_percentile=advisory.epss_percentile,
        published_at=advisory.published_at,
        github_reviewed=advisory.github_reviewed,
        cves=sorted(c.cve_id for c in advisory.cves),
        packages=[PackageRef(ecosystem=p.ecosystem, name=p.name) for p in advisory.packages],
        technologies=technologies_for_ecosystems(
            {p.ecosystem for p in advisory.packages}, technologies
        ),
    )


def _ranges(ranges_json: str | None) -> list[dict[str, Any]]:
    """Decode the stored OSV ranges; unreadable data becomes an empty list."""
    if not ranges_json:
        return []
    try:
        decoded = json.loads(ranges_json)
    except ValueError:
        return []
    return [r for r in decoded if isinstance(r, dict)] if isinstance(decoded, list) else []


@router.get(
    "/advisories",
    summary="List and search package advisories",
    description=(
        "Security advisories for packages (Maven, npm...) from the GitHub Advisory "
        "Database via OSV. Paginated; all filters are optional and combine with AND. "
        "`technology` uses the OSV ecosystems of that technology in technologies.yaml. "
        "`package` matches part of the package name. `q` searches the advisory id, "
        "summary, CVE ids and package names. `has_cve=false` returns advisories "
        "without a CVE. Rows without a value for the sorted field always come last. "
        "An unknown technology or an invalid value returns 422."
    ),
    response_model=AdvisoryPage,
    responses={
        200: {
            "content": {
                "application/json": {
                    "example": {
                        "items": [
                            {
                                "id": "GHSA-jfh8-c2jp-5v3q",
                                "summary": "Remote code injection in Log4j",
                                "severity": "CRITICAL",
                                "epss_score": 0.99999,
                                "epss_percentile": 1.0,
                                "published_at": "2021-12-10T00:40:56",
                                "github_reviewed": True,
                                "cves": ["CVE-2021-44228"],
                                "packages": [
                                    {
                                        "ecosystem": "Maven",
                                        "name": "org.apache.logging.log4j:log4j-core",
                                    }
                                ],
                                "technologies": ["Java"],
                            }
                        ],
                        "total": 1,
                        "page": 1,
                        "page_size": 25,
                    }
                }
            }
        }
    },
)
def list_advisories(
    session: SessionDep,
    technologies: TechnologiesDep,
    technology: Annotated[
        list[str] | None, Query(description="Technology name; repeat for several (OR).")
    ] = None,
    package: Annotated[
        str | None, Query(max_length=200, description="Package name contains.")
    ] = None,
    severity: Annotated[list[Severity] | None, Query()] = None,
    min_epss: Annotated[float | None, Query(ge=0, le=1)] = None,
    published_from: Annotated[date | None, Query(description="Published on or after.")] = None,
    published_to: Annotated[date | None, Query(description="Published on or before.")] = None,
    has_cve: Annotated[bool | None, Query()] = None,
    q: Annotated[str | None, Query(max_length=200, description="Free text, id or CVE.")] = None,
    sort: AdvisorySortField = "published",
    order: SortOrder = "desc",
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 25,
) -> AdvisoryPage:
    if published_from and published_to and published_from > published_to:
        raise HTTPException(422, "published_from must not be after published_to")

    ecosystems = None
    if technology:
        by_name = {t.name.lower(): t for t in technologies}
        unknown = [name for name in technology if name.lower() not in by_name]
        if unknown:
            available = ", ".join(t.name for t in technologies)
            raise HTTPException(422, f"Unknown technology {unknown[0]!r}. Available: {available}")
        ecosystems = [e for name in technology for e in by_name[name.lower()].osv_ecosystems]

    filters = AdvisoryFilters(
        ecosystems=ecosystems,
        package=package,
        severities=list(severity or []),
        min_epss=min_epss,
        published_from=published_from,
        published_to=published_to,
        has_cve=has_cve,
        q=q.strip() if q else None,
    )
    rows, total = search_advisories(
        session, filters, sort=sort, order=order, page=page, page_size=page_size
    )
    return AdvisoryPage(
        items=[_summary(a, technologies) for a in rows], total=total, page=page, page_size=page_size
    )


@router.get(
    "/advisories/{advisory_id}",
    summary="Get one package advisory",
    description=(
        "Full detail of an advisory: affected packages with version ranges and fixed "
        "versions, CVE ids (with a flag telling whether the CVE has a page here), and "
        "references. The id is case-insensitive. Returns 404 if unknown and 422 if the id "
        "is not a valid GHSA id. Missing data is `null`; version ranges are not interpreted."
    ),
    response_model=AdvisoryDetail,
    responses={404: {"description": "Advisory not found."}, 422: {"description": "Invalid id."}},
)
def get_advisory(
    advisory_id: str, session: SessionDep, technologies: TechnologiesDep
) -> AdvisoryDetail:
    cleaned = advisory_id.strip()
    normalized = "GHSA-" + cleaned[5:].lower() if cleaned[:5].upper() == "GHSA-" else cleaned
    if not GHSA_RE.fullmatch(normalized):
        raise HTTPException(422, "Invalid advisory id; expected format GHSA-xxxx-xxxx-xxxx")
    advisory = session.scalars(
        select(Advisory)
        .where(Advisory.id == normalized)
        .options(
            selectinload(Advisory.cves),
            selectinload(Advisory.packages),
            selectinload(Advisory.references),
        )
    ).first()
    if advisory is None:
        raise HTTPException(404, f"{normalized} not found")

    cve_ids = sorted(c.cve_id for c in advisory.cves)
    known = set(
        session.scalars(select(Vulnerability.cve_id).where(Vulnerability.cve_id.in_(cve_ids)))
    )
    return AdvisoryDetail(
        id=advisory.id,
        summary=advisory.summary,
        details=advisory.details,
        severity=advisory.severity,
        cvss_vector=advisory.cvss_vector,
        epss_score=advisory.epss_score,
        epss_percentile=advisory.epss_percentile,
        published_at=advisory.published_at,
        modified_at=advisory.modified_at,
        github_reviewed=advisory.github_reviewed,
        technologies=technologies_for_ecosystems(
            {p.ecosystem for p in advisory.packages}, technologies
        ),
        cves=[AdvisoryCveRef(cve_id=c, in_database=c in known) for c in cve_ids],
        packages=[
            AdvisoryPackage(
                ecosystem=p.ecosystem,
                name=p.name,
                fixed_versions=[
                    v.strip() for v in (p.fixed_versions or "").split(",") if v.strip()
                ],
                ranges=_ranges(p.ranges_json),
            )
            for p in advisory.packages
        ],
        references=[r.url for r in advisory.references],
    )
