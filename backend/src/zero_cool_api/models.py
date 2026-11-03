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


class Advisory(Base):
    """A security advisory for packages (GitHub Advisory Database, via OSV).

    Unlike :class:`Vulnerability`, an advisory is identified by its own id
    (e.g. ``GHSA-jfh8-c2jp-5v3q``) because not every advisory has a CVE.
    """

    __tablename__ = "advisories"
    __table_args__ = (Index("ix_advisory_published_at", "published_at"),)

    id: Mapped[str] = mapped_column(primary_key=True)
    summary: Mapped[str | None]
    details: Mapped[str | None]
    severity: Mapped[str | None]  # LOW / MEDIUM / HIGH / CRITICAL (GitHub's MODERATE -> MEDIUM)
    cvss_vector: Mapped[str | None]  # the score is not provided by OSV and is never computed
    published_at: Mapped[datetime | None]
    modified_at: Mapped[datetime | None]
    github_reviewed: Mapped[bool | None]

    # Highest EPSS among the advisory's CVEs; None when it has no CVE or none has a score.
    epss_score: Mapped[float | None]
    epss_percentile: Mapped[float | None]

    cves: Mapped[list["AdvisoryCve"]] = relationship(
        back_populates="advisory", cascade="all, delete-orphan"
    )
    packages: Mapped[list["AdvisoryPackage"]] = relationship(
        back_populates="advisory", cascade="all, delete-orphan"
    )
    references: Mapped[list["AdvisoryReference"]] = relationship(
        back_populates="advisory", cascade="all, delete-orphan"
    )


class AdvisoryCve(Base):
    """A CVE id an advisory is also known as. An advisory may have several or none."""

    __tablename__ = "advisory_cves"

    id: Mapped[int] = mapped_column(primary_key=True)
    advisory_id: Mapped[str] = mapped_column(ForeignKey("advisories.id"), index=True)
    cve_id: Mapped[str] = mapped_column(index=True)

    advisory: Mapped[Advisory] = relationship(back_populates="cves")


class AdvisoryPackage(Base):
    """A package affected by an advisory, with its version ranges as OSV reports them."""

    __tablename__ = "advisory_packages"
    __table_args__ = (Index("ix_advisory_package_name", "ecosystem", "name"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    advisory_id: Mapped[str] = mapped_column(ForeignKey("advisories.id"), index=True)
    ecosystem: Mapped[str]  # as in OSV, e.g. Maven, npm
    name: Mapped[str]
    # JSON list of OSV range objects, stored untouched: the app does not interpret
    # version ranges (Maven and npm order versions differently).
    ranges_json: Mapped[str | None]
    # Comma separated versions that fix the advisory, extracted from the ranges.
    fixed_versions: Mapped[str | None]

    advisory: Mapped[Advisory] = relationship(back_populates="packages")


class AdvisoryReference(Base):
    """An external link related to an advisory."""

    __tablename__ = "advisory_references"

    id: Mapped[int] = mapped_column(primary_key=True)
    advisory_id: Mapped[str] = mapped_column(ForeignKey("advisories.id"), index=True)
    url: Mapped[str]

    advisory: Mapped[Advisory] = relationship(back_populates="references")


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
