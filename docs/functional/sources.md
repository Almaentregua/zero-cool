# Data sources

Where the information in the app comes from, what each source tells you and
what it does not. The sources complement each other: each one answers a
different question about the same vulnerability (CVE).

## Summary

| Source | Question it answers | What it provides | Status |
|--------|--------------------|------------------|--------|
| **CISA KEV** | Is it already being exploited in real attacks? | The list of exploited CVEs, with vendor, product, name, short description, date added, remediation due date and ransomware use | Available (v1a) |
| **NVD** (NIST) | How severe is it, and what are the technical details? | Official description, CVSS score and vector, publication and modification dates, reference links | Available (v1a) |
| **EPSS** (FIRST) | How likely is it to be exploited soon? | Probability (0 to 1) of exploitation in the next 30 days, and its percentile | Available (v1a) |
| **OSV.dev** (GitHub advisories) | Which packages and versions are affected, and which fix them? | Package advisories for Maven and npm with affected packages, version ranges and fixed versions | Data imported; screens planned (v1b) |

## How the three main numbers differ

- **KEV is about what already happened.** Someone exploited it. It is the
  strongest signal for prioritizing, but it is a yes/no flag and says nothing
  about how severe the flaw is.
- **CVSS (from NVD) is about technical severity.** How much damage it could do.
  A CVE can score 9.8 and never be exploited.
- **EPSS is about what may happen.** A statistical estimate, not a fact, and it
  changes every day.

Example, Log4Shell (`CVE-2021-44228`): it is in KEV, used in ransomware
campaigns, has CVSS 10.0 and an EPSS close to 100%. A CVE with CVSS 9.8 and
EPSS 1% is severe on paper but unlikely to be seen in practice.

## CISA KEV

- **Role in the app:** defines which CVEs exist in the list. Everything else is
  added on top of it.
- **Size:** about 1,800 entries, one small file.
- **Limit:** it only contains what CISA has already confirmed as exploited, so it
  is a short, high-signal list rather than every vulnerability.
- **Vendor and product** are free text written by CISA (for example `Apache` /
  `Log4j2`). That is why technologies are matched by those exact names.
- **Ransomware:** CISA's `Known` is shown as "Yes", `Unknown` as "No".

## NVD

- **Role in the app:** adds severity and detail to the KEV CVEs. It replaces
  CISA's short description with the official one.
- **Speed:** the slowest source because it is queried one CVE at a time. With an
  API key the first full run takes about 20 minutes; without a key, around 3
  hours. Later runs skip CVEs fetched in the last 7 days.
- **Missing scores:** new CVEs often have no CVSS score yet. The app then shows
  "Not available"; it never estimates one.
- **Several ratings:** when a CVE has more than one CVSS rating, the app uses the
  newest CVSS version and prefers NVD's own rating.

## EPSS

- **Role in the app:** adds the exploitation probability to the KEV CVEs.
- **Speed:** very fast and needs no key.
- **Always current:** scores are recalculated daily by FIRST, so each run replaces
  the previous values. The date of the score is not stored yet.
- **Gaps:** a few CVEs may have no EPSS score; they show "Not available".
- **How to read it:** the probability is for the next 30 days. The percentile says
  how the CVE ranks against all others (a percentile of 0.9 means higher than 90%
  of CVEs).

## OSV.dev and GitHub advisories

KEV, NVD and EPSS describe **the CVE**, the vulnerability in the abstract. Package
advisories describe **which package and which version** is affected, for Maven (Java)
and npm (Node.js).

- **One source in practice.** OSV republishes GitHub's security advisories for these
  ecosystems, so the app reads them from OSV only. Using the GitHub API as well would
  return the same advisories.
- **Not every advisory has a CVE.** About 8% do not. That is why advisories are kept in
  their own list, identified by their own id (for example `GHSA-jfh8-c2jp-5v3q`).
- **Volume.** About 14,700 advisories, compared with about 1,800 KEV vulnerabilities. Few
  of them are in KEV (67 CVEs), which is normal: KEV only lists what is known to be
  exploited.
- **Severity** is GitHub's level (Low, Medium, High, Critical). Only the CVSS vector is
  available, not the numeric score, and the app does not calculate one.
- **Version ranges** are shown as reported. The app does not tell you whether a specific
  version of your project is affected.
- **Not included:** reports of malicious packages, and withdrawn advisories.
- **EPSS** is added to advisories that have a CVE. If an advisory lists several CVEs, the
  highest EPSS is shown. Advisories without a CVE show "Not available".

## Keeping data fresh

Data is refreshed manually with `make ingest`. See
[Pages](pages.md) for the screens and the [Glossary](glossary.md) for the terms. How
each source is fetched, validated and stored is explained in
[technical ingestion](../technical/ingestion.md).

## A note on trust

Data from these sources is shown as received. The app never invents or fills in
technical details: if a source does not provide a value, it is shown as "Not
available".
