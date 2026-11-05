# Research sources

Code: `backend/src/zero_cool_api/research/`. Used by Investigations
([ADR 0004](adr/0004-investigations-on-demand-and-snapshots.md)).

## Interface
A research source is a class with `id`, `name`, `cache_ttl_seconds` and
`fetch(cve_id) -> Fetched` (see `research/base.py`). It returns normalized data, or
`data=None` when it has nothing about the CVE, or raises `FetchError` when it cannot be
reached. It never returns the source's raw format.

Every consulted source produces a `SourceResult` (`source`, `source_name`, `cve_id`,
`status`, `message`, `origin_url`, `retrieved_at`, `data`), including sources with no
data or an error, so reports can show which sources were checked. This maps one to one
to `report_source_results`.

## Runner (`research/runner.py`)
`research(cve_id, sources, cache=..., force=..., timeout_seconds=...)`:
- Validates the CVE id first (`CVE-YYYY-NNNN+`); an invalid id calls no source.
- Runs the sources in parallel, one thread each, and returns results in the given order.
- A source failing, crashing or exceeding the timeout (default 15 s) only turns its own
  result into `error`. Messages shown never include exception details (those go to the log).
- Cache: in memory, per source and CVE, expiring after the source's `cache_ttl_seconds`.
  Only `ok` and `no_data` are cached; errors are always retried. `force=True` is a manual
  refresh. The cache is lost when the API restarts.
- A timed-out request cannot be killed; its thread finishes in the background.

## Current sources (`research/adapters/`, listed in `research/registry.py`)

| Id | Source | Where the answer comes from | Cache | Notes |
|----|--------|-----------------------------|-------|-------|
| `kev` | CISA KEV | Local database (ingested catalog) | 5 min | "Not in KEV" is an answer (`in_kev: false`); error if the catalog was never ingested |
| `nvd` | NVD (NIST) | Live API, any CVE | 24 h | Uses `NVD_API_KEY`; calls are serialized to respect the rate limit |
| `epss` | EPSS (FIRST) | Live API | 1 h | Score and percentile, 0 to 1 |
| `osv` | OSV / GitHub Advisories | Local database | 5 min | Only the ecosystems in `technologies.yaml`; says so when empty |
| `cve_org` | CVE.org (CNA record) | Live API (CVE Services) | 6 h | What the CNA that assigned the CVE published: description, CWE, ratings, affected products, links |
| `vulnrichment` | CISA Vulnrichment | Same API request | 6 h | CISA's container: SSVC (exploitation, automatable, technical impact), CVSS, CWE. "No data" when CISA did not enrich the CVE |
| `cwe` | MITRE CWE | Live API (`cwe-api.mitre.org`) | 24 h | Official name and definition of each CWE listed in the CVE record; says who listed it (`cna`, `cisa` or both) |

`cwe` depends on the CVE record: it takes the CWE ids from it (at most 10). An id MITRE does
not know is shown with no name or text (nothing is invented); views are not weaknesses and
are treated the same way. `/cwe/{id}` only returns the kind of entry, so a weakness costs two
requests (kind, then details); entries are memoized for 24 h. Verified against the live API.

`cve_org` and `vulnrichment` read the same record (`sources/cve_org.py`, one request shared
through a 60 s memo) but are separate blocks because they have different authors; their
values are never merged. The record format was checked against the live API
(`https://cveawg.mitre.org/api/cve/{id}`; unknown ids answer HTTP 404) and two real
records are kept as test fixtures. Rejected records are shown with their rejection reason.

Differences from the first design: NVD is always queried live (cached 24 h) instead of
reading stored data first, which keeps one code path for KEV and non-KEV CVEs.

## Adding a source
Create a module in `research/adapters/` with a class that follows the interface and add it
to `build_sources` in `research/registry.py`. Tests use mocked HTTP, never real APIs.

## Comparing snapshots (`research/diff.py`)
`diff_result(old, new)` compares a stored block with a fresh one, ignoring timestamps, and
returns `None` when nothing changed. Used by the report refresh.
