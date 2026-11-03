"""Response models of the API.

Fields that are ``None`` mean "not available": the data was not provided by any
source. They are never replaced by zero or placeholder text.
"""

from datetime import date, datetime

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
