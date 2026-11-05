"""Compare two snapshots of the same source's answer, to show what changed on a refresh."""

from typing import Any, Literal

from pydantic import BaseModel

from zero_cool_api.research.base import SourceResult

ChangeKind = Literal["new", "status", "data", "refresh_failed"]


class Change(BaseModel):
    """What changed in one source's block for one CVE.

    Attributes:
        kind: ``new`` (no previous snapshot), ``status`` (ok / no_data / error changed),
            ``data`` (same status, different content) or ``refresh_failed`` (the new
            query failed, so the previous snapshot was kept).
        before_status: Status of the previous snapshot, if any.
        after_status: Status of the new result.
        fields: For ``data``, the top-level keys whose values changed.
    """

    cve_id: str
    source: str
    source_name: str
    kind: ChangeKind
    before_status: str | None
    after_status: str
    fields: list[str] = []


def _changed_fields(before: dict[str, Any] | None, after: dict[str, Any] | None) -> list[str]:
    before, after = before or {}, after or {}
    return sorted(k for k in before.keys() | after.keys() if before.get(k) != after.get(k))


def diff_result(old: SourceResult | None, new: SourceResult) -> Change | None:
    """Describe how a refreshed result differs from the stored one.

    Parameters:
        old: The stored snapshot, or ``None`` if the source was not in the report.
        new: The freshly obtained result.

    Returns:
        The change, or ``None`` if nothing changed. Timestamps are ignored.
    """

    def change(kind: ChangeKind, before: str | None, fields: list[str] | None = None) -> Change:
        return Change(
            cve_id=new.cve_id,
            source=new.source,
            source_name=new.source_name,
            kind=kind,
            before_status=before,
            after_status=new.status,
            fields=fields or [],
        )

    if old is None:
        return change("new", None)
    if new.status == "error" and old.status != "error":
        return change("refresh_failed", old.status)
    if old.status != new.status:
        return change("status", old.status)
    fields = _changed_fields(old.data, new.data)
    if fields:
        return change("data", old.status, fields)
    return None
