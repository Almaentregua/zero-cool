"""Endpoints for vulnerabilities and technologies."""

from datetime import date
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from zero_cool_api.api.deps import SessionDep, TechnologiesDep
from zero_cool_api.api.schemas import (
    AdvisoryLink,
    PackageRef,
    TechnologyOut,
    VulnerabilityDetail,
    VulnerabilityPage,
    VulnerabilitySummary,
)
from zero_cool_api.models import Advisory, AdvisoryCve, Vulnerability
from zero_cool_api.queries import (
    SortField,
    SortOrder,
    VulnerabilityFilters,
    search,
    technologies_for,
)
from zero_cool_api.sources.kev import CVE_RE
from zero_cool_api.technologies import Technology

router = APIRouter(prefix="/api")

Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _values(vuln: Vulnerability, model: type[VulnerabilitySummary]) -> dict[str, object]:
    """Copy the plain columns a response model asks for from the database row."""
    computed = {"technologies", "references", "advisories"}
    return {name: getattr(vuln, name) for name in model.model_fields if name not in computed}


def _summary(vuln: Vulnerability, techs: list[Technology]) -> VulnerabilitySummary:
    return VulnerabilitySummary(
        **_values(vuln, VulnerabilitySummary),  # type: ignore[arg-type]
        technologies=technologies_for(vuln, techs),
    )


@router.get(
    "/technologies",
    summary="List technologies",
    description=(
        "Technologies defined in technologies.yaml. Use their `name` as the "
        "`technology` filter of the vulnerability list."
    ),
    response_model=list[TechnologyOut],
    responses={
        200: {
            "content": {
                "application/json": {
                    "example": [
                        {
                            "name": "Java",
                            "osv_ecosystems": ["Maven"],
                            "products": ["Apache / Log4j2", "Oracle / WebLogic Server"],
                        }
                    ]
                }
            }
        }
    },
)
def list_technologies(technologies: TechnologiesDep) -> list[TechnologyOut]:
    return [
        TechnologyOut(
            name=t.name,
            osv_ecosystems=t.osv_ecosystems,
            products=[f"{p.vendor} / {p.product}" for p in t.products],
        )
        for t in technologies
    ]


@router.get(
    "/vulnerabilities",
    summary="List and search vulnerabilities",
    description=(
        "Paginated list. All filters are optional and combine with AND. "
        "`q` searches the CVE id, title, description, vendor and product "
        "(case-insensitive). `severity` can be repeated "
        "(`?severity=HIGH&severity=CRITICAL`). `ransomware=true` returns only "
        "those known to be used in ransomware; `false` only those known not to be. "
        "Rows without a value for the sorted field always come last. "
        "An unknown technology or an invalid value returns 422."
    ),
    response_model=VulnerabilityPage,
    responses={
        200: {
            "content": {
                "application/json": {
                    "example": {
                        "items": [
                            {
                                "cve_id": "CVE-2021-44228",
                                "title": "Apache Log4j2 Remote Code Execution Vulnerability",
                                "vendor": "Apache",
                                "product": "Log4j2",
                                "cvss_score": 10.0,
                                "severity": "CRITICAL",
                                "epss_score": 0.99999,
                                "epss_percentile": 1.0,
                                "is_kev": True,
                                "ransomware_use": True,
                                "date_added": "2021-12-10",
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
def list_vulnerabilities(
    session: SessionDep,
    technologies: TechnologiesDep,
    added_from: Annotated[date | None, Query(description="Added on or after (YYYY-MM-DD).")] = None,
    added_to: Annotated[date | None, Query(description="Added on or before (YYYY-MM-DD).")] = None,
    technology: Annotated[
        list[str] | None, Query(description="Technology name; repeat for several (OR).")
    ] = None,
    vendor: Annotated[str | None, Query(max_length=100, description="Vendor contains.")] = None,
    product: Annotated[str | None, Query(max_length=100, description="Product contains.")] = None,
    min_cvss: Annotated[float | None, Query(ge=0, le=10)] = None,
    severity: Annotated[list[Severity] | None, Query()] = None,
    min_epss: Annotated[float | None, Query(ge=0, le=1)] = None,
    ransomware: Annotated[bool | None, Query()] = None,
    q: Annotated[str | None, Query(max_length=200, description="Free text or CVE id.")] = None,
    sort: SortField = "date_added",
    order: SortOrder = "desc",
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 25,
) -> VulnerabilityPage:
    if added_from and added_to and added_from > added_to:
        raise HTTPException(422, "added_from must not be after added_to")

    products = None
    if technology:
        by_name = {t.name.lower(): t for t in technologies}
        unknown = [name for name in technology if name.lower() not in by_name]
        if unknown:
            available = ", ".join(t.name for t in technologies)
            raise HTTPException(422, f"Unknown technology {unknown[0]!r}. Available: {available}")
        products = [p for name in technology for p in by_name[name.lower()].products]

    filters = VulnerabilityFilters(
        added_from=added_from,
        added_to=added_to,
        products=products,
        vendor=vendor,
        product=product,
        min_cvss=min_cvss,
        severities=list(severity or []),
        min_epss=min_epss,
        ransomware=ransomware,
        q=q.strip() if q else None,
    )
    rows, total = search(session, filters, sort=sort, order=order, page=page, page_size=page_size)
    return VulnerabilityPage(
        items=[_summary(v, technologies) for v in rows],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/vulnerabilities/{cve_id}",
    summary="Get one vulnerability",
    description=(
        "Full detail of a CVE, including references. The id is case-insensitive "
        "(`cve-2021-44228` works). Returns 404 if the CVE is not in the database "
        "and 422 if the id is not a valid CVE id. Missing data is `null`."
    ),
    response_model=VulnerabilityDetail,
    responses={404: {"description": "CVE not found."}, 422: {"description": "Invalid CVE id."}},
)
def get_vulnerability(
    cve_id: str, session: SessionDep, technologies: TechnologiesDep
) -> VulnerabilityDetail:
    normalized = cve_id.strip().upper()
    if not CVE_RE.fullmatch(normalized):
        raise HTTPException(422, "Invalid CVE id; expected format CVE-YYYY-NNNN")
    vuln = session.get(Vulnerability, normalized)
    if vuln is None:
        raise HTTPException(404, f"{normalized} not found")
    advisories = session.scalars(
        select(Advisory)
        .join(AdvisoryCve)
        .where(AdvisoryCve.cve_id == normalized)
        .options(selectinload(Advisory.packages))
        .order_by(Advisory.id)
    ).all()
    return VulnerabilityDetail(
        **_values(vuln, VulnerabilityDetail),  # type: ignore[arg-type]
        technologies=technologies_for(vuln, technologies),
        references=[r.url for r in vuln.references],
        advisories=[
            AdvisoryLink(
                id=a.id,
                summary=a.summary,
                severity=a.severity,
                packages=[PackageRef(ecosystem=p.ecosystem, name=p.name) for p in a.packages],
            )
            for a in advisories
        ],
    )
