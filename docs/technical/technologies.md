# technologies.yaml

Defines which technologies the app tracks. **Adding one means adding an entry;
no code changes.** The file is read and validated by
`backend/src/zero_cool_api/technologies.py`; an invalid file raises a clear
error (missing file, bad YAML, wrong shape, duplicate names).

Location: `backend/technologies.yaml` (override with `TECHNOLOGIES_FILE`).

Matching against vulnerabilities ignores letter case but needs the full vendor
and product text to match, exactly as CISA KEV writes them (for example
`Apache` / `Log4j2`, `Oracle` / `WebLogic Server`). Look up the exact spelling
in the KEV catalog or in the app after ingestion.

```yaml
technologies:
  - name: Java                 # shown in the technology filter (unique, case-insensitive)
    osv_ecosystems: [Maven]    # OSV ecosystem names; `make ingest-osv` imports their advisories
    products:                  # vendor/product pairs exactly as written in KEV
      - {vendor: Apache, product: Log4j2}
```

To add Go, append:

```yaml
  - name: Go
    osv_ecosystems: [Go]
    products:
      - {vendor: Golang, product: Go}
```

The initial lists were taken from the real KEV catalog (checked 2026-11-02) but
are a starting point: KEV has many more Java-related products (for example
Apache Tomcat variants or Spring components). Extend them as needed.
