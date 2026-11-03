"""Building the vulnerability list query from the user's filters."""

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import date
from typing import Literal

from sqlalchemy import ColumnElement, and_, func, or_, select
from sqlalchemy.orm import InstrumentedAttribute, Session, selectinload

from zero_cool_api.models import Advisory, AdvisoryCve, AdvisoryPackage, Vulnerability
from zero_cool_api.technologies import Product, Technology

SortField = Literal["date_added", "cvss", "epss"]
SortOrder = Literal["asc", "desc"]

_SORT_COLUMNS = {
    "date_added": Vulnerability.date_added,
    "cvss": Vulnerability.cvss_score,
    "epss": Vulnerability.epss_score,
}


@dataclass
class VulnerabilityFilters:
    """Filters of the vulnerability list; ``None``/empty means "no filter"."""

    added_from: date | None = None
    added_to: date | None = None
    products: list[Product] | None = None  # expanded from the technology filter
    vendor: str | None = None
    product: str | None = None
    min_cvss: float | None = None
    severities: list[str] = field(default_factory=list)
    min_epss: float | None = None
    ransomware: bool | None = None
    q: str | None = None


def _contains(
    column: InstrumentedAttribute[str] | InstrumentedAttribute[str | None], text: str
) -> ColumnElement[bool]:
    """Case-insensitive "contains" with LIKE wildcards in ``text`` escaped."""
    escaped = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return column.ilike(f"%{escaped}%", escape="\\")


def build_conditions(filters: VulnerabilityFilters) -> list[ColumnElement[bool]]:
    """Translate filters into SQL conditions (all values are bound parameters).

    Parameters:
        filters: The user's filters.

    Returns:
        Conditions to be combined with AND.
    """
    v = Vulnerability
    conditions: list[ColumnElement[bool]] = []
    if filters.added_from is not None:
        conditions.append(v.date_added >= filters.added_from)
    if filters.added_to is not None:
        conditions.append(v.date_added <= filters.added_to)
    if filters.products is not None:
        # A technology without products matches nothing, hence the empty OR.
        pairs = [
            and_(
                func.lower(v.vendor) == p.vendor.lower(), func.lower(v.product) == p.product.lower()
            )
            for p in filters.products
        ]
        conditions.append(or_(*pairs) if pairs else or_(False))
    if filters.vendor:
        conditions.append(_contains(v.vendor, filters.vendor))
    if filters.product:
        conditions.append(_contains(v.product, filters.product))
    if filters.min_cvss is not None:
        conditions.append(v.cvss_score >= filters.min_cvss)
    if filters.severities:
        conditions.append(v.severity.in_(filters.severities))
    if filters.min_epss is not None:
        conditions.append(v.epss_score >= filters.min_epss)
    if filters.ransomware is True:
        conditions.append(v.ransomware_use.is_(True))
    elif filters.ransomware is False:
        conditions.append(v.ransomware_use.is_(False))
    if filters.q:
        conditions.append(
            or_(
                *(
                    _contains(c, filters.q)
                    for c in (v.cve_id, v.title, v.description, v.vendor, v.product)
                )
            )
        )
    return conditions


def search(
    session: Session,
    filters: VulnerabilityFilters,
    *,
    sort: SortField = "date_added",
    order: SortOrder = "desc",
    page: int = 1,
    page_size: int = 25,
) -> tuple[list[Vulnerability], int]:
    """Run the list query.

    Parameters:
        session: Open session.
        filters: Filters to apply.
        sort: Column to sort by. Rows without a value always go last.
        order: ``asc`` or ``desc``.
        page: 1-based page number.
        page_size: Rows per page.

    Returns:
        ``(rows of the page, total number of matching rows)``.
    """
    conditions = build_conditions(filters)
    total = session.scalar(select(func.count()).select_from(Vulnerability).where(*conditions)) or 0
    column = _SORT_COLUMNS[sort]
    ordering = column.desc() if order == "desc" else column.asc()
    rows = session.scalars(
        select(Vulnerability)
        .where(*conditions)
        .order_by(ordering.nulls_last(), Vulnerability.cve_id)
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return list(rows), total


def technologies_for(vuln: Vulnerability, technologies: list[Technology]) -> list[str]:
    """Names of the tracked technologies a vulnerability belongs to.

    Parameters:
        vuln: The vulnerability.
        technologies: Technologies from ``technologies.yaml``.

    Returns:
        Technology names, in file order.
    """
    if vuln.vendor is None or vuln.product is None:
        return []
    key = (vuln.vendor.lower(), vuln.product.lower())
    return [
        t.name
        for t in technologies
        if any((p.vendor.lower(), p.product.lower()) == key for p in t.products)
    ]


AdvisorySortField = Literal["published", "epss"]


@dataclass
class AdvisoryFilters:
    """Filters of the advisory list; ``None``/empty means "no filter"."""

    ecosystems: list[str] | None = None  # expanded from the technology filter
    package: str | None = None
    severities: list[str] = field(default_factory=list)
    min_epss: float | None = None
    published_from: date | None = None
    published_to: date | None = None
    has_cve: bool | None = None
    q: str | None = None


def build_advisory_conditions(filters: AdvisoryFilters) -> list[ColumnElement[bool]]:
    """Translate advisory filters into SQL conditions (bound parameters only).

    Parameters:
        filters: The user's filters.

    Returns:
        Conditions to be combined with AND.
    """
    a = Advisory
    conditions: list[ColumnElement[bool]] = []
    if filters.ecosystems is not None:
        # A technology without ecosystems matches nothing, hence the empty IN.
        lowered = [e.lower() for e in filters.ecosystems]
        conditions.append(
            a.id.in_(
                select(AdvisoryPackage.advisory_id).where(
                    func.lower(AdvisoryPackage.ecosystem).in_(lowered)
                )
            )
        )
    if filters.package:
        conditions.append(
            a.id.in_(
                select(AdvisoryPackage.advisory_id).where(
                    _contains(AdvisoryPackage.name, filters.package)
                )
            )
        )
    if filters.severities:
        conditions.append(a.severity.in_(filters.severities))
    if filters.min_epss is not None:
        conditions.append(a.epss_score >= filters.min_epss)
    if filters.published_from is not None:
        conditions.append(func.date(a.published_at) >= filters.published_from.isoformat())
    if filters.published_to is not None:
        conditions.append(func.date(a.published_at) <= filters.published_to.isoformat())
    if filters.has_cve is not None:
        with_cve = a.id.in_(select(AdvisoryCve.advisory_id))
        conditions.append(with_cve if filters.has_cve else ~with_cve)
    if filters.q:
        conditions.append(
            or_(
                _contains(a.id, filters.q),
                _contains(a.summary, filters.q),
                a.id.in_(
                    select(AdvisoryCve.advisory_id).where(_contains(AdvisoryCve.cve_id, filters.q))
                ),
                a.id.in_(
                    select(AdvisoryPackage.advisory_id).where(
                        _contains(AdvisoryPackage.name, filters.q)
                    )
                ),
            )
        )
    return conditions


def search_advisories(
    session: Session,
    filters: AdvisoryFilters,
    *,
    sort: AdvisorySortField = "published",
    order: SortOrder = "desc",
    page: int = 1,
    page_size: int = 25,
) -> tuple[list[Advisory], int]:
    """Run the advisory list query.

    Parameters:
        session: Open session.
        filters: Filters to apply.
        sort: ``published`` or ``epss``. Rows without a value always go last.
        order: ``asc`` or ``desc``.
        page: 1-based page number.
        page_size: Rows per page.

    Returns:
        ``(rows of the page, total number of matching rows)``.
    """
    conditions = build_advisory_conditions(filters)
    total = session.scalar(select(func.count()).select_from(Advisory).where(*conditions)) or 0
    column = Advisory.published_at if sort == "published" else Advisory.epss_score
    ordering = column.desc() if order == "desc" else column.asc()
    rows = session.scalars(
        select(Advisory)
        .where(*conditions)
        .options(selectinload(Advisory.cves), selectinload(Advisory.packages))
        .order_by(ordering.nulls_last(), Advisory.id)
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return list(rows), total


def technologies_for_ecosystems(
    ecosystems: Iterable[str], technologies: list[Technology]
) -> list[str]:
    """Names of the tracked technologies that cover any of the given OSV ecosystems.

    Parameters:
        ecosystems: Ecosystems of an advisory's packages (for example ``Maven``).
        technologies: Technologies from ``technologies.yaml``.

    Returns:
        Technology names, in file order.
    """
    wanted = {e.lower() for e in ecosystems}
    return [t.name for t in technologies if wanted & {e.lower() for e in t.osv_ecosystems}]
