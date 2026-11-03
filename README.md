# CVE Research App

Web application to stay up to date with new security vulnerabilities, with as
much detail as possible. Browse vulnerabilities by date, technology, severity,
exploitation status and more, and search by CVE ID or free text.

## Status

Project setup. See `docs/worklog/README.md` for the current state.

## Structure

- `backend/` - Python API (FastAPI, managed with uv).
- `frontend/` - Web UI (React + Vite + TypeScript).
- `docs/` - Functional and technical documentation, ADRs, work log.

## Requirements

- Python 3.12+ and [uv](https://docs.astral.sh/uv/)
- Node.js 20+ and npm
- make

## Getting started

```bash
make install   # install backend and frontend dependencies
make dev       # API on :8000, frontend on :5173
```

Open http://localhost:5173. API docs (OpenAPI) are at http://localhost:8000/docs.

## Configuration

```bash
make setup   # creates backend/.env from backend/.env.example (never overwrites)
```

Then edit `backend/.env`. Real `.env` files are never committed, and
`make` commands load `backend/.env` automatically when it exists.

**NVD API key (optional but recommended).** Request a free key at
https://nvd.nist.gov/developers/request-an-api-key and put it in
`backend/.env` as `NVD_API_KEY=...`. Without it, NVD enrichment still works but
is about 10x slower. Never paste the key into code, logs or chats.

| File | Variable | Purpose |
|------|----------|---------|
| `backend/.env.example` | `CORS_ORIGINS` | Comma separated origins allowed to call the API |
| `backend/.env.example` | `NVD_API_KEY` | Optional NVD key (secret, only in `backend/.env`) |
| `backend/.env.example` | `DATABASE_PATH` | SQLite file location (default `data/zero_cool.db`) |
| `backend/.env.example` | `TECHNOLOGIES_FILE` | Path to `technologies.yaml` (default `technologies.yaml`) |
| `frontend/.env.example` | `VITE_API_URL` | Backend URL used by the dev proxy |

## Commands

Run `make help` for the full list. Main targets:

| Command | Description |
|---------|-------------|
| `make install` | Install all dependencies |
| `make dev` | Run backend and frontend together |
| `make backend` / `make frontend` | Run one side only |
| `make setup` | Create `backend/.env` from the example |
| `make ingest-kev` | Download CISA KEV into the local database (manual, safe to repeat) |
| `make ingest-nvd` | Enrich KEV CVEs with NVD data (`LIMIT=5` to try, `FORCE=1` to refetch) |
| `make ingest-epss` | Add EPSS exploitation probabilities to the KEV CVEs |
| `make test` | Run backend (pytest) and frontend (Vitest) tests |
| `make lint` / `make format` | Lint / format |
| `make typecheck` | mypy (backend) and tsc (frontend) |
| `make check` | Lint, format check, types and tests; run before finishing a task |
| `make build` | Production build of the frontend |

## Documentation

- What each page/API offers: `docs/functional/pages.md` and `docs/technical/api.md`
- v1 scope: `docs/technical/scope.md`
- Functional docs: `docs/functional/`
- Technical docs: `docs/technical/`
- Architecture decisions: `docs/technical/adr/`
- Work log: `docs/worklog/`
