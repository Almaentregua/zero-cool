# Changelog

All notable user-visible changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Initial project structure and documentation.
- Backend skeleton (FastAPI) with a health endpoint, and frontend skeleton (React + Vite + TypeScript).
- SQLite connection helper (ADR 0001) and Vitest for the frontend.
- API endpoints to list, filter and search vulnerabilities, read one CVE in detail, and list technologies.
- Ingestion of CISA KEV, NVD and EPSS data (`make ingest`).
- Makefile with commands to install, run, test, lint and build.
