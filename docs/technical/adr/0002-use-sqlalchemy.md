# 0002. Use SQLAlchemy 2.0 as ORM

- Status: Accepted
- Date: 2026-11-02

## Context
The vulnerability list needs many optional, combinable filters (date,
technology, vendor/product, CVSS, EPSS, ransomware) plus text search. Building
that with hand-written SQL strings is verbose and error prone.

## Decision
Use SQLAlchemy 2.0 (synchronous, typed `Mapped[...]` models). Tables are created
with `create_all` for now.

## Alternatives considered
- Plain `sqlite3`: no dependency, but dynamic filters become manual string building.
- SQLModel: thinner, but adds another layer on top of SQLAlchemy and Pydantic.

## Consequences
- Filters compose as Python expressions and values are always parameterized (no SQL injection).
- One new dependency.
- No migrations yet: schema changes during v1 mean recreating the local database.
  Add Alembic (with its own ADR) before the schema needs to preserve data.
