# Changelog

All notable user-visible changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Docs section in the web app: a searchable guide to the data sources (CISA KEV, NVD, EPSS, OSV.dev, GitHub Advisories, CVE.org, CISA Vulnrichment, MITRE CWE) and to security concepts (CVE, CVSS and its vector, CWE, CPE, EPSS, KEV, SSVC, package advisories, versions and more), with examples, diagrams and links to official pages. Terms across the app now have a "?" link to their topic.
- Initial project structure and documentation.
- Backend skeleton (FastAPI) with a health endpoint, and frontend skeleton (React + Vite + TypeScript).
- SQLite connection helper (ADR 0001) and Vitest for the frontend.
- Package advisories for Maven and npm (from OSV): ingestion, EPSS scores, API endpoints, and web pages to list, filter, search and read them, linked with the CVE pages.
- Web pages: vulnerability list with search, filters, sorting and pagination, and a detail page per CVE.
- API endpoints to list, filter and search vulnerabilities, read one CVE in detail, and list technologies.
- Ingestion of CISA KEV, NVD and EPSS data (`make ingest`).
- Makefile with commands to install, run, test, lint and build.
