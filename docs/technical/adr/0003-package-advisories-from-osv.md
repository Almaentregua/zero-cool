# 0003. Package advisories: OSV as the only source, stored separately

- Status: Accepted
- Date: 2026-11-03

## Context
v1b adds package vulnerabilities for Maven and npm. The two planned sources, OSV.dev
and the GitHub Advisory Database, overlap almost completely: measured on 2026-11-02,
OSV's Maven dump has 7,222 `GHSA-` records and 2 others, and its npm dump has 8,073
`GHSA-` records plus 222,975 malicious-package reports (`MAL-`). The `GHSA-` records are
GitHub's advisories in OSV format. Between 82% (npm) and 97% (Maven) have a CVE alias,
and only 67 of the 1,766 KEV CVEs have a Maven or npm advisory.

## Decision
- Ingest only OSV dumps (`<ecosystem>/all.zip`), keeping `GHSA-*` records. The GitHub API
  is not used. Ecosystems come from `osv_ecosystems` in `technologies.yaml`.
- Store advisories in their own tables (`advisories`, `advisory_cves`,
  `advisory_packages`, `advisory_references`), keyed by the advisory id, not by CVE,
  because many advisories have no CVE.
- Exclude malicious-package reports (`MAL-`) and withdrawn advisories.
- Keep version ranges exactly as OSV reports them; the app does not evaluate whether a
  version is affected (Maven and npm order versions differently).
- Normalize severity (`MODERATE` becomes `MEDIUM`). OSV gives only the CVSS vector, so the
  score is "not available"; it is never computed.
- An advisory's EPSS is the highest EPSS among its CVEs.

## Alternatives considered
- GitHub REST API: gives a CVSS score, but needs a token for practical rate limits and
  returns the same advisories, so it adds duplicates to reconcile.
- Mixing advisories into `vulnerabilities`: the primary key is the CVE, which many
  advisories lack, and the list would gain about 15,000 rows without KEV or ransomware data.
- Ingesting `MAL-` reports: they would multiply the npm data by 28 and are a different problem.

## Consequences
- The first npm download is about 220 MB (97% malware that is discarded). An ETag cache
  avoids repeating it.
- No GitHub-only fields (such as the numeric CVSS score) until the API is added, if ever.
- New tables only: existing databases keep their data.
