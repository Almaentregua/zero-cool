# 0001. Use SQLite as the database in v1

- Status: Accepted
- Date: 2026-11-02

## Context
The app needs to store normalized CVE data from several sources. v1 is a
single-user, single-process application with no deployment requirements yet.

## Decision
Use SQLite through Python's standard `sqlite3` module. The file location comes
from the `DATABASE_PATH` environment variable.

## Alternatives considered
- Postgres: more capable, but adds a server to install and operate before it is needed.

## Consequences
- Zero setup and trivial test databases (`tmp_path`).
- Single writer: ingestion and API writes must not run concurrently at scale.
- No ORM or migration tool chosen yet; add one (with its own ADR) when the schema is defined.
- Moving to Postgres later means keeping SQL access behind a small data layer.
