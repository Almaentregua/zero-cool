# v1 scope

Personal use, a single person.

## v1a - Known exploited vulnerabilities
- Ingest the CISA KEV catalog.
- Enrich only the CVEs in KEV with NVD data (description, CVSS, CPE, references).
- Add the EPSS score for each of those CVEs.

## v1b - Package vulnerabilities
- Ingest OSV.dev and GitHub Security Advisories for the Maven and npm ecosystems.

## Features
- Filters: date added, technology, vendor/product, severity (CVSS),
  minimum EPSS, used in ransomware campaigns.
- Search by CVE ID and by free text.
- Vulnerability list and a detail page for each vulnerability.

## Technologies
Initially Java (Maven) and Node.js (npm). They are defined in
`technologies.yaml` (name, OSV ecosystems, vendor/product pairs). Adding a
technology is only adding an entry; no code changes.

## Out of scope for now
Users and login, alerts, personal stack list, AI summaries, cloud deployment.
