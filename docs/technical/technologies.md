# technologies.yaml

Defines which technologies the app tracks. **Adding one means adding an entry;
no code changes.** The file is read and validated by
`backend/src/zero_cool_api/technologies.py`; an invalid file raises a clear
error (missing file, bad YAML, wrong shape, duplicate names).

Location: `backend/technologies.yaml` (override with `TECHNOLOGIES_FILE`).

```yaml
technologies:
  - name: Java                 # shown in the technology filter (unique, case-insensitive)
    osv_ecosystems: [Maven]    # OSV / GitHub ecosystems (used in v1b)
    products:                  # vendor/product pairs as written in KEV / NVD, lowercase
      - {vendor: apache, product: log4j}
```

To add Go, append:

```yaml
  - name: Go
    osv_ecosystems: [Go]
    products:
      - {vendor: golang, product: go}
```

The initial vendor/product lists are a starting point and should be reviewed
against real KEV data once ingestion exists.
