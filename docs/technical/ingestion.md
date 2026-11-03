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

## Where data goes
`backend/data/zero_cool.db` (override with `DATABASE_PATH`). Git ignores it.
To start from scratch, delete the file and ingest again.

## Rate limits
KEV has no documented rate limit but is only fetched when you run the command.
NVD (next step) has strict limits and will be throttled.
