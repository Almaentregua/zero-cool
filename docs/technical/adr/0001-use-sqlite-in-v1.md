# 0001. Use SQLite as the database in v1

- Status: Accepted
- Date: 2026-11-02

## Context
The app needs to store normalized CVE data from several sources. v1 is a
single-user, single-process application with no deployment requirements yet.

## Decision
Use SQLite. The file location comes from the `DATABASE_PATH` environment
variable. Access goes through SQLAlchemy (see ADR 0002).

## Alternatives considered
- Postgres: more capable, but adds a server to install and operate before it is needed.

## Consequences
- Zero setup and trivial test databases (`tmp_path`).
- Single writer: ingestion and API writes must not run concurrently at scale.
- Moving to Postgres later is mostly a connection-string change thanks to SQLAlchemy.
