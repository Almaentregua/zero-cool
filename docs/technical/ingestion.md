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

## Where data goes
`backend/data/zero_cool.db` (override with `DATABASE_PATH`). Git ignores it.
To start from scratch, delete the file and ingest again.

## Rate limits
KEV has no documented rate limit but is only fetched when you run the command.
NVD (next step) has strict limits and will be throttled.
