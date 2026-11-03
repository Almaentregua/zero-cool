# Data model

Every source is normalized into the app's own model (`backend/src/zero_cool_api/models.py`).
The rest of the app never depends on a source's format. Missing data is `NULL`
and shown as "not available"; values are never guessed.

## `vulnerabilities`

| Column | Source | Notes |
|--------|--------|-------|
| `cve_id` (PK) | KEV | e.g. `CVE-2021-44228` |
| `title`, `description` | KEV / NVD | |
| `vendor`, `product` | KEV | Stored exactly as KEV writes them (e.g. `Apache`, `Log4j2`); used to match technologies |
| `is_kev`, `date_added`, `kev_due_date` | KEV | `date_added` is the "date added" filter |
| `ransomware_use` | KEV | `NULL` = unknown |
| `cvss_score`, `cvss_vector`, `published_at`, `modified_at` | NVD | |
| `nvd_fetched_at` | NVD | When NVD was last queried, even if it had no data; drives the 7-day skip |
| `severity` | derived | From `cvss_score`: LOW <4, MEDIUM <7, HIGH <9, CRITICAL >=9 |
| `epss_score`, `epss_percentile` | EPSS | 0 to 1; refreshed on every EPSS run |

## `references`
`id`, `cve_id` (FK), `url`: external links per vulnerability (NVD). Only `http(s)` URLs are kept.

## Package advisories (v1b)

Separate from `vulnerabilities` because an advisory is identified by its own id and many
have no CVE. See [ADR 0003](adr/0003-package-advisories-from-osv.md).

### `advisories`
| Column | Notes |
|--------|-------|
| `id` (PK) | e.g. `GHSA-jfh8-c2jp-5v3q` |
| `summary`, `details` | `details` is Markdown from the source: show as plain text |
| `severity` | LOW / MEDIUM / HIGH / CRITICAL (GitHub's MODERATE becomes MEDIUM) |
| `cvss_vector` | The score is not provided by OSV and is never computed |
| `published_at`, `modified_at` | |
| `github_reviewed` | Whether GitHub reviewed it |
| `epss_score`, `epss_percentile` | Highest EPSS among its CVEs; `NULL` if it has no CVE or no score |

### `advisory_cves`
`advisory_id` (FK), `cve_id`. An advisory can have several CVEs or none. Joining on
`cve_id` links an advisory to a row of `vulnerabilities` when that CVE is in KEV.

### `advisory_packages`
`advisory_id` (FK), `ecosystem` (Maven, npm), `name`, `ranges_json` (OSV ranges, untouched),
`fixed_versions` (comma separated, extracted from the ranges). One advisory can affect
many packages (Log4Shell lists 10).

### `advisory_references`
`advisory_id` (FK), `url` (http/https only).

Withdrawn advisories and malicious-package reports are not stored.

## Technologies
Not stored in the database. They live in `technologies.yaml`; filtering by
technology expands to its vendor/product pairs.

OSV and GitHub advisories (v1b) will extend this model when implemented.
