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
| `epss_score`, `epss_percentile` | EPSS | 0 to 1 |

## `references`
`id`, `cve_id` (FK), `url`: external links per vulnerability (NVD). Only `http(s)` URLs are kept.

## Technologies
Not stored in the database. They live in `technologies.yaml`; filtering by
technology expands to its vendor/product pairs.

OSV and GitHub advisories (v1b) will extend this model when implemented.
