# 0004. Investigations: on-demand research sources and snapshot reports

- Status: Accepted
- Date: 2026-11-04

## Context
The "Investigations" feature (draft in `docs/technical/design/cve-research.md`) lets the
user research any CVE, saved or not in KEV, gather what every source knows, and save a
report to continue later. This conflicts with two current rules: NVD enrichment is limited
to KEV CVEs (`scope.md`), and the app only shows data it has ingested. The feature must
also accept new sources over time without redesign.

## Decision
- **Any CVE can be investigated.** For a CVE the app does not have, sources are queried on
  demand (NVD with the existing `NVD_API_KEY`, EPSS, and the new ones) and results are
  cached. KEV membership is always reported, including "not in KEV". Ingestion keeps its
  KEV-only NVD enrichment; on-demand fetching only happens inside an investigation.
- **Research sources are plugins** with one common interface: given a CVE id, return
  normalized findings (source, kind, payload, retrieved-at, origin link) or "not
  available". The page and the report never depend on a source's own format. Adding a
  source means adding one module.
- **First batch of new sources:** CVE.org record, CISA Vulnrichment (same record) and
  MITRE CWE. Later sources are decided in their own ADR when they are added (rate limits,
  licensing).
- **Reports are snapshots.** Saving stores the findings as they were (`report_findings`).
  A refresh action re-fetches and shows what changed. Reports live in their own tables
  (`reports`, `report_cves`, `report_findings`) and never modify `vulnerabilities`.
- **Notes are Markdown**, one field per report, stored as text and rendered without raw
  HTML. Findings and notes are untrusted input.
- **Failures are per source.** One source failing or lacking data does not fail the
  investigation; that block shows "not available" with the reason.

## Alternatives considered
- Live view only (no snapshots): simpler, but a report would change under the user, so
  there is no reproducibility and no "what changed" view.
- Ingesting NVD for all CVEs: about 300,000 records and slow even with a key; the user
  needs a handful of CVEs, not the whole database.
- Writing on-demand results into `vulnerabilities`: mixes curated KEV data with ad hoc
  lookups and would break the list filters (KEV, date added) that assume KEV rows.
- A fixed set of sources hard-coded in the page: every new source would touch the core.

## Consequences
- `scope.md` must be updated: NVD on-demand for non-KEV CVEs is allowed inside
  investigations only.
- On-demand calls share NVD's rate limit with ingestion; they need the same retries and
  backoff, a cache with a TTL, and a per-source timeout.
- Snapshots grow the database; findings are small JSON payloads, which is acceptable for
  a single user on SQLite (ADR 0001).
- The Markdown renderer must be chosen with sanitization as a hard requirement.
