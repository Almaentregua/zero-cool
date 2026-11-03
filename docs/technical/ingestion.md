# Ingestion

Ingestion is **manual** in v1: you run a command when you want fresh data.
There is no scheduler.

## CISA KEV (v1a, step 2)

```bash
make ingest-kev
```

Flow: `sources/kev.py` downloads the catalog -> each record is validated and
normalized -> `ingest/kev.py` writes it to SQLite.

- **Safe to repeat.** Existing CVEs are updated, new ones created. Fields from
  other sources (NVD, EPSS) are never overwritten by KEV. KEV's short description
  is only used while no other description exists.
- **Validation.** CVE ids must look like `CVE-YYYY-NNNN`; dates must be valid.
  Invalid records are skipped and counted in the log; the rest are stored.
- **Sanitization.** Control characters are removed and text is limited to 5000
  characters. HTML is **not** stripped: it is stored as text and must be
  rendered as plain text by the frontend.
- **Ransomware flag.** `Known` -> true, `Unknown` -> false, anything else -> not available.
- **Retries.** `http.get_json` retries network errors and HTTP 429/5xx with
  exponential backoff (1 s, 2 s, 4 s, 8 s; up to 4 retries) and honors `Retry-After`.
  Other errors fail right away with exit code 1 and a clear message.
- **Cache.** The KEV feed is one small file fetched on demand, so there is no
  cache for it. Caching will matter for NVD/EPSS (next steps).

## NVD enrichment (v1a, step 3)

```bash
make ingest-kev               # first, so there are CVEs to enrich
make ingest-nvd LIMIT=5       # try with 5 CVEs
make ingest-nvd               # all KEV CVEs
make ingest-nvd FORCE=1       # ignore the freshness window and refetch
```

Only CVEs flagged as KEV are queried. For each one, NVD provides the English
description, CVSS score and vector, publication/modification dates and
reference links. NVD's description replaces KEV's short one.

- **CVSS choice.** The newest CVSS version available (4.0, 3.1, 3.0, then 2.0);
  within it, NVD's own ("Primary") rating is preferred. Severity is derived from the score.
- **Missing data.** If NVD has no record or no score yet (common for new CVEs),
  the fields stay empty ("not available"). Nothing is estimated.
- **Rate limit.** NVD allows 50 requests per 30 s with a key and 5 without. The
  client waits 0.65 s (with key) or 6.5 s (without) between requests. With a key,
  the first full run of ~1,800 CVEs takes about 20 minutes; without one, around 3 hours.
- **Resumable and cheap to repeat.** A CVE queried in the last 7 days is skipped.
  Progress is saved every 25 CVEs, so Ctrl+C or a failure loses little.
  Failed CVEs are not marked as fetched, so the next run retries them.
- **API key.** Read from `NVD_API_KEY`, sent only as a request header, never
  logged. If NVD rejects it (401/403) the run stops with a clear message.
- **Exit code.** 1 if any CVE failed, so failures are not silent.

## EPSS (v1a, step 4)

```bash
make ingest-epss
```

Queries FIRST's public EPSS API (no key needed) for every KEV CVE, 100 CVEs per
request, so about 18 requests in total (a few seconds).

- **Values.** `epss_score` is the probability (0 to 1) of exploitation in the next
  30 days; `epss_percentile` says how it ranks against all CVEs. The API sends them as
  text; values outside 0-1 or not numeric are discarded.
- **Always refreshed.** EPSS is recalculated daily, so every run overwrites the
  previous values. Run it whenever you want current numbers.
- **Unknown CVEs.** If EPSS has no score for a CVE, the field stays empty
  ("not available") or keeps its previous value. Nothing is estimated.
- **Safety.** Only the CVE ids we asked for are accepted from the response.
- **Failure.** If any request fails after retries, nothing is written and the
  command exits with code 1.

## Package advisories from OSV (v1b, step 2)

```bash
make ingest-osv
```

Imports GitHub's security advisories for the ecosystems listed in
`osv_ecosystems` of `technologies.yaml` (today Maven and npm). Adding an
ecosystem is only adding it to that file. Why OSV and not the GitHub API:
[ADR 0003](adr/0003-package-advisories-from-osv.md).

Flow: download `<ecosystem>/all.zip` from OSV -> read the `GHSA-*` records inside the
zip -> validate and normalize -> store in the `advisories*` tables.

- **Cache.** The zips are kept in `backend/data/cache/` with their `ETag`. When OSV says
  nothing changed, nothing is downloaded: a repeated run takes about 12 s instead of
  about 50 s. The first run downloads about 230 MB (npm is 220 MB, mostly malware reports
  that are discarded). A failed download never replaces the previous good file.
- **Safe zip reading.** The zip is never extracted to disk. Members are read one by one
  in memory; names with a path, members over 5 MB, non-`GHSA-` records and invalid JSON are
  skipped. A download over 1 GB is aborted.
- **What is imported.** Only `GHSA-*` records that affect a wanted ecosystem. Malicious-package
  reports (`MAL-*`) are ignored. Withdrawn advisories are not stored, and are deleted if
  they were stored before.
- **Normalization.** `MODERATE` becomes `MEDIUM`. Only the CVSS vector is stored (OSV has no
  score and it is never computed). Version ranges are kept as OSV reports them; fixed
  versions are listed separately. Only `http(s)` links are kept. Dates are stored as UTC.
- **Invalid records** are skipped and counted in the log; they never stop the rest.
- **Repeatable.** An advisory is rewritten only when its `modified` date changed; EPSS
  values already stored on it are preserved. An advisory present in both the Maven and npm
  dumps is stored once.
- **Retries.** Same exponential backoff as the other sources. Failures exit with code 1.

First real run (2026-11-03): 7,102 Maven and 7,663 npm advisories (14,703 in total; 13,519
with a CVE), 120 and 410 withdrawn ones skipped, 67 KEV CVEs with an advisory.

## Everything at once

```bash
make ingest
```

Runs `ingest-kev`, `ingest-osv`, `ingest-epss` and `ingest-nvd` in that order and
stops at the first failure. EPSS runs before NVD on purpose: it takes seconds, while the
first NVD run takes ~20 minutes (with a key). If NVD is interrupted, KEV and EPSS
data are already stored and re-running `make ingest` resumes NVD where it stopped.
After the first run, `make ingest` is quick because NVD skips CVEs fetched in the
last 7 days.

You can still run each step on its own (`make ingest-kev`, `make ingest-osv`,
`make ingest-epss`, `make ingest-nvd`). KEV must come first on an empty database.

## Where data goes
`backend/data/zero_cool.db` (override with `DATABASE_PATH`). Git ignores it.
To start from scratch, delete the file and ingest again.

## Rate limits
KEV has no documented rate limit but is only fetched when you run the command.
NVD (next step) has strict limits and will be throttled.
