"""Endpoints for saved investigation reports (see ADR 0004)."""

import json
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, HTTPException, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from zero_cool_api.api.deps import ResearchSourcesDep, ResultCacheDep, SessionDep
from zero_cool_api.models import Report, ReportCve, ReportSourceResult
from zero_cool_api.research.base import ResearchSource, SourceResult, normalize_cve_id
from zero_cool_api.research.diff import Change, diff_result
from zero_cool_api.research.runner import ResultCache, research

router = APIRouter(prefix="/api")

MAX_CVES = 10  # each CVE costs one query per source, so keep a report small
MAX_NOTES = 100_000
Title = Annotated[str, Field(min_length=1, max_length=200, description="Report title.")]
Notes = Annotated[str, Field(max_length=MAX_NOTES, description="Markdown notes (untrusted text).")]
Status = Annotated[str, Field(pattern="^(open|done)$", description="`open` or `done`.")]
CveList = Annotated[list[str], Field(description="CVE ids, e.g. `CVE-2021-44228`.")]


class ReportCreate(BaseModel):
    """Body to create a report; every CVE is investigated and its answers are saved."""

    title: Title
    cves: CveList = Field(min_length=1, max_length=MAX_CVES)
    notes: Notes = ""


class ReportUpdate(BaseModel):
    """Body to edit a report. Only the fields sent are changed."""

    title: Title | None = None
    notes: Notes | None = None
    status: Status | None = None
    add_cves: CveList = Field(default_factory=list, max_length=MAX_CVES)
    remove_cves: CveList = Field(default_factory=list, max_length=MAX_CVES)


class ReportSummary(BaseModel):
    """A report as listed."""

    id: int
    title: str
    status: str
    cves: list[str]
    created_at: datetime
    updated_at: datetime


class ReportDetail(ReportSummary):
    """A full report: notes plus one saved block per CVE and source."""

    notes: str
    results: list[SourceResult] = Field(
        description="Snapshot taken when the CVE was added or last refreshed."
    )


class RefreshResponse(BaseModel):
    """A refreshed report and what changed compared to the previous snapshot."""

    report: ReportDetail
    changes: list[Change] = Field(
        description="Only what changed. A failed refresh keeps the previous snapshot."
    )


def _now() -> datetime:
    # The database stores naive UTC datetimes (same as the ingestion code).
    return datetime.now(UTC).replace(tzinfo=None)


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC)


def _cve_ids(raw: list[str]) -> list[str]:
    """Normalize and de-duplicate CVE ids keeping order; invalid ids give a 422."""
    seen: dict[str, None] = {}
    for item in raw:
        try:
            seen.setdefault(normalize_cve_id(item), None)
        except ValueError as exc:
            raise HTTPException(422, f"Invalid CVE id: {item[:30]!r}") from exc
    return list(seen)


def _load(session: SessionDep, report_id: int) -> Report:
    report = session.scalars(
        select(Report)
        .where(Report.id == report_id)
        .options(selectinload(Report.cves), selectinload(Report.results))
    ).first()
    if report is None:
        raise HTTPException(404, f"Report {report_id} not found")
    return report


def _stored(row: ReportSourceResult, names: dict[str, str]) -> SourceResult:
    data = json.loads(row.payload_json) if row.payload_json else None
    return SourceResult(
        source=row.source,
        source_name=names.get(row.source, row.source),
        cve_id=row.cve_id,
        status=row.status,  # type: ignore[arg-type]
        message=row.message,
        origin_url=row.origin_url,
        retrieved_at=_aware(row.retrieved_at),
        data=data,
    )


def _summary(report: Report) -> ReportSummary:
    return ReportSummary(
        id=report.id,
        title=report.title,
        status=report.status,
        cves=[c.cve_id for c in sorted(report.cves, key=lambda c: c.id)],
        created_at=_aware(report.created_at),
        updated_at=_aware(report.updated_at),
    )


def _detail(report: Report, sources: list[ResearchSource]) -> ReportDetail:
    names = {s.id: s.name for s in sources}
    order = {c.cve_id: i for i, c in enumerate(sorted(report.cves, key=lambda c: c.id))}
    source_order = {s.id: i for i, s in enumerate(sources)}
    rows = sorted(
        report.results,
        key=lambda r: (order.get(r.cve_id, 99), source_order.get(r.source, 99)),
    )
    return ReportDetail(
        **_summary(report).model_dump(),
        notes=report.notes,
        results=[_stored(r, names) for r in rows],
    )


def _investigate(
    cve_id: str,
    sources: list[ResearchSource],
    cache: ResultCache,
    *,
    force: bool = False,
) -> list[SourceResult]:
    return research(cve_id, sources, cache=cache, force=force)


def _save(report: Report, result: SourceResult) -> None:
    """Insert or replace the stored block for ``result``'s CVE and source."""
    row = next(
        (r for r in report.results if r.cve_id == result.cve_id and r.source == result.source),
        None,
    )
    if row is None:
        row = ReportSourceResult(cve_id=result.cve_id, source=result.source)
        report.results.append(row)
    row.status = result.status
    row.message = result.message
    row.origin_url = result.origin_url
    row.retrieved_at = result.retrieved_at.astimezone(UTC).replace(tzinfo=None)
    row.payload_json = json.dumps(result.data) if result.data is not None else None


@router.post(
    "/reports",
    summary="Create an investigation report",
    description=(
        "Investigates every CVE (up to 10) across all sources and saves the answers as a "
        "snapshot together with the title and Markdown notes. Notes are untrusted text: "
        "clients must render them without raw HTML. Invalid CVE ids return 422 and nothing "
        "is saved. This can take several seconds per CVE."
    ),
    response_model=ReportDetail,
    status_code=201,
    responses={422: {"description": "Invalid body or CVE id."}},
)
def create_report(
    body: ReportCreate, session: SessionDep, sources: ResearchSourcesDep, cache: ResultCacheDep
) -> ReportDetail:
    cves = _cve_ids(body.cves)
    now = _now()
    report = Report(title=body.title.strip(), notes=body.notes, created_at=now, updated_at=now)
    if not report.title:
        raise HTTPException(422, "The title cannot be blank")
    for cve in cves:
        report.cves.append(ReportCve(cve_id=cve))
        for result in _investigate(cve, sources, cache):
            _save(report, result)
    session.add(report)
    session.commit()
    return _detail(_load(session, report.id), sources)


@router.get(
    "/reports",
    summary="List saved reports",
    description="Saved reports, most recently updated first (without notes or source blocks).",
    response_model=list[ReportSummary],
)
def list_reports(session: SessionDep) -> list[ReportSummary]:
    reports = session.scalars(
        select(Report).options(selectinload(Report.cves)).order_by(Report.updated_at.desc())
    )
    return [_summary(r) for r in reports]


@router.get(
    "/reports/{report_id}",
    summary="Open a saved report",
    description=(
        "The report with its notes and the saved block of every source for every CVE, "
        "exactly as they were when saved or last refreshed. Nothing is queried. 404 if unknown."
    ),
    response_model=ReportDetail,
    responses={404: {"description": "Report not found."}},
)
def get_report(report_id: int, session: SessionDep, sources: ResearchSourcesDep) -> ReportDetail:
    return _detail(_load(session, report_id), sources)


@router.patch(
    "/reports/{report_id}",
    summary="Edit a report",
    description=(
        "Change the title, notes or status, and add or remove CVEs. Added CVEs are "
        "investigated now; removed ones lose their saved blocks. A report keeps at least one "
        "and at most 10 CVEs. Invalid ids return 422 and nothing changes."
    ),
    response_model=ReportDetail,
    responses={404: {"description": "Report not found."}, 422: {"description": "Invalid body."}},
)
def update_report(
    report_id: int,
    body: ReportUpdate,
    session: SessionDep,
    sources: ResearchSourcesDep,
    cache: ResultCacheDep,
) -> ReportDetail:
    report = _load(session, report_id)
    add = [c for c in _cve_ids(body.add_cves) if c not in {x.cve_id for x in report.cves}]
    remove = set(_cve_ids(body.remove_cves))
    final = ({c.cve_id for c in report.cves} - remove) | set(add)
    if not 1 <= len(final) <= MAX_CVES:
        raise HTTPException(422, f"A report needs between 1 and {MAX_CVES} CVEs")
    if body.title is not None:
        if not body.title.strip():
            raise HTTPException(422, "The title cannot be blank")
        report.title = body.title.strip()
    if body.notes is not None:
        report.notes = body.notes
    if body.status is not None:
        report.status = body.status
    for cve in remove:
        report.cves = [c for c in report.cves if c.cve_id != cve]
        report.results = [r for r in report.results if r.cve_id != cve]
    for cve in add:
        report.cves.append(ReportCve(cve_id=cve))
        for result in _investigate(cve, sources, cache):
            _save(report, result)
    report.updated_at = _now()
    session.commit()
    return _detail(_load(session, report_id), sources)


@router.post(
    "/reports/{report_id}/refresh",
    summary="Refresh a report from the sources",
    description=(
        "Queries every source again for every CVE (ignoring the cache), replaces the saved "
        "blocks and returns what changed. If a source fails during the refresh, its previous "
        "block is kept and the change is reported as `refresh_failed`, so a refresh never "
        "destroys good data. Notes are not touched."
    ),
    response_model=RefreshResponse,
    responses={404: {"description": "Report not found."}},
)
def refresh_report(
    report_id: int, session: SessionDep, sources: ResearchSourcesDep, cache: ResultCacheDep
) -> RefreshResponse:
    report = _load(session, report_id)
    names = {s.id: s.name for s in sources}
    changes: list[Change] = []
    for cve in [c.cve_id for c in sorted(report.cves, key=lambda c: c.id)]:
        old = {r.source: _stored(r, names) for r in report.results if r.cve_id == cve}
        for result in _investigate(cve, sources, cache, force=True):
            change = diff_result(old.get(result.source), result)
            if change is not None:
                changes.append(change)
            if change is None or change.kind != "refresh_failed":
                _save(report, result)
    report.updated_at = _now()
    session.commit()
    return RefreshResponse(report=_detail(_load(session, report_id), sources), changes=changes)


@router.delete(
    "/reports/{report_id}",
    summary="Delete a report",
    description="Permanently deletes the report, its notes and its saved blocks. 404 if unknown.",
    status_code=204,
    responses={404: {"description": "Report not found."}},
)
def delete_report(report_id: int, session: SessionDep) -> Response:
    session.delete(_load(session, report_id))
    session.commit()
    return Response(status_code=204)
