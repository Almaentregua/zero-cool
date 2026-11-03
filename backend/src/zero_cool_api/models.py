"""Database models: the app's own normalized representation of a vulnerability.

External sources (KEV, NVD, EPSS, ...) are converted to these models at
ingestion time; the rest of the app never sees source-specific formats.
Missing data is stored as ``NULL`` and shown as "not available", never guessed.
"""

from datetime import date, datetime

from sqlalchemy import ForeignKey, Index
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Declarative base for all models."""


class Vulnerability(Base):
    """One CVE with data merged from every source that knows about it."""

    __tablename__ = "vulnerabilities"
    __table_args__ = (
        Index("ix_vuln_vendor_product", "vendor", "product"),
        Index("ix_vuln_date_added", "date_added"),
    )

    cve_id: Mapped[str] = mapped_column(primary_key=True)
    title: Mapped[str | None]
    description: Mapped[str | None]
    vendor: Mapped[str | None]
    product: Mapped[str | None]

    # KEV
    is_kev: Mapped[bool] = mapped_column(default=False)
    date_added: Mapped[date | None]
    ransomware_use: Mapped[bool | None]  # None = unknown
    kev_due_date: Mapped[date | None]

    # NVD
    cvss_score: Mapped[float | None]
    cvss_vector: Mapped[str | None]
    severity: Mapped[str | None]  # LOW / MEDIUM / HIGH / CRITICAL, derived from cvss_score
    published_at: Mapped[datetime | None]
    modified_at: Mapped[datetime | None]
    nvd_fetched_at: Mapped[datetime | None]  # when NVD was last queried (even if it had no data)

    # EPSS
    epss_score: Mapped[float | None]
    epss_percentile: Mapped[float | None]

    references: Mapped[list["Reference"]] = relationship(
        back_populates="vulnerability", cascade="all, delete-orphan"
    )


class Reference(Base):
    """An external link (advisory, patch, write-up) related to a vulnerability."""

    __tablename__ = "references"

    id: Mapped[int] = mapped_column(primary_key=True)
    cve_id: Mapped[str] = mapped_column(ForeignKey("vulnerabilities.cve_id"), index=True)
    url: Mapped[str]

    vulnerability: Mapped[Vulnerability] = relationship(back_populates="references")


def severity_from_cvss(score: float | None) -> str | None:
    """Map a CVSS base score to its qualitative severity.

    Parameters:
        score: CVSS base score from 0.0 to 10.0, or ``None`` if unknown.

    Returns:
        ``LOW``, ``MEDIUM``, ``HIGH`` or ``CRITICAL``; ``None`` when the score is
        missing or ``0.0`` (CVSS "None" rating) or out of range.
    """
    if score is None or score <= 0.0 or score > 10.0:
        return None
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"
