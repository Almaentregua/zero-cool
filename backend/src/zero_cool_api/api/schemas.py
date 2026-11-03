"""Response models of the API.

Fields that are ``None`` mean "not available": the data was not provided by any
source. They are never replaced by zero or placeholder text.
"""

from datetime import date, datetime
from typing import Any

from pydantic import BaseModel, Field


class VulnerabilitySummary(BaseModel):
    """A vulnerability as shown in the list."""

    cve_id: str = Field(examples=["CVE-2021-44228"])
    title: str | None = Field(description="Short name from CISA KEV.")
    vendor: str | None
    product: str | None
    cvss_score: float | None = Field(description="CVSS base score, 0 to 10.", examples=[10.0])
    severity: str | None = Field(
        description="LOW, MEDIUM, HIGH or CRITICAL, derived from the CVSS score.",
        examples=["CRITICAL"],
    )
    epss_score: float | None = Field(
        description="Probability (0 to 1) of exploitation in the next 30 days.", examples=[0.97]
    )
    epss_percentile: float | None = Field(description="Rank against all CVEs, 0 to 1.")
    is_kev: bool = Field(description="True if CISA reports it as actively exploited.")
    ransomware_use: bool | None = Field(
        description="True if known to be used in ransomware campaigns; null if unknown."
    )
    date_added: date | None = Field(description="Date it was added to the KEV catalog.")
    technologies: list[str] = Field(
        description="Tracked technologies it belongs to (from technologies.yaml).",
        examples=[["Java"]],
    )


class VulnerabilityDetail(VulnerabilitySummary):
    """Full information of one vulnerability."""

    description: str | None = Field(
        description="Plain text. Render it as text, never as HTML.",
    )
    cvss_vector: str | None
    published_at: datetime | None
    modified_at: datetime | None
    kev_due_date: date | None = Field(description="CISA remediation due date.")
    references: list[str] = Field(description="External links (http/https only).")
    advisories: list["AdvisoryLink"] = Field(
        default_factory=list,
        description="Package advisories (Maven, npm) that mention this CVE; may be empty.",
    )


class VulnerabilityPage(BaseModel):
    """One page of the vulnerability list."""

    items: list[VulnerabilitySummary]
    total: int = Field(description="Number of vulnerabilities matching the filters.")
    page: int
    page_size: int


class TechnologyOut(BaseModel):
    """A technology available in the filters."""

    name: str = Field(examples=["Java"])
    osv_ecosystems: list[str] = Field(examples=[["Maven"]])
    products: list[str] = Field(
        description="Vendor/product pairs it covers, as 'Vendor / Product'.",
        examples=[["Apache / Log4j2"]],
    )


class PackageRef(BaseModel):
    """A package named by an advisory (list view)."""

    ecosystem: str = Field(examples=["Maven"])
    name: str = Field(examples=["org.apache.logging.log4j:log4j-core"])


class AdvisorySummary(BaseModel):
    """A package advisory as shown in the list."""

    id: str = Field(examples=["GHSA-jfh8-c2jp-5v3q"])
    summary: str | None
    severity: str | None = Field(
        description="LOW, MEDIUM, HIGH or CRITICAL.", examples=["CRITICAL"]
    )
    epss_score: float | None = Field(
        description="Highest EPSS among the advisory's CVEs; null if it has no CVE or no score."
    )
    epss_percentile: float | None
    published_at: datetime | None
    github_reviewed: bool | None
    cves: list[str] = Field(description="CVE ids of the advisory; may be empty.")
    packages: list[PackageRef]
    technologies: list[str] = Field(description="Tracked technologies covering its ecosystems.")


class AdvisoryPackage(BaseModel):
    """A package affected by an advisory (detail view)."""

    ecosystem: str
    name: str
    fixed_versions: list[str] = Field(description="Versions that fix the advisory; may be empty.")
    ranges: list[dict[str, Any]] = Field(
        description="Version ranges exactly as OSV reports them (not interpreted)."
    )


class AdvisoryCveRef(BaseModel):
    """A CVE of an advisory and whether this app has a page for it."""

    cve_id: str
    in_database: bool = Field(
        description="True if the CVE is in the KEV list, so /api/vulnerabilities/{cve_id} exists."
    )


class AdvisoryDetail(BaseModel):
    """Full information of one advisory."""

    id: str
    summary: str | None
    details: str | None = Field(description="Markdown from the source. Render it as plain text.")
    severity: str | None
    cvss_vector: str | None = Field(description="The numeric score is not available from OSV.")
    epss_score: float | None
    epss_percentile: float | None
    published_at: datetime | None
    modified_at: datetime | None
    github_reviewed: bool | None
    technologies: list[str]
    cves: list[AdvisoryCveRef]
    packages: list[AdvisoryPackage]
    references: list[str] = Field(description="External links (http/https only).")


class AdvisoryPage(BaseModel):
    """One page of the advisory list."""

    items: list[AdvisorySummary]
    total: int
    page: int
    page_size: int


class AdvisoryLink(BaseModel):
    """An advisory related to a KEV vulnerability."""

    id: str
    summary: str | None
    severity: str | None
    packages: list[PackageRef]
