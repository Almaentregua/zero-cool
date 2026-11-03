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
| **OSV.dev** | Which package versions are affected, and which fix them? | Vulnerabilities in packages (Maven and npm), with affected and fixed versions | Planned (v1b) |
| **GitHub Security Advisories** | Same question, from GitHub's advisory database | Security advisories for the same ecosystems | Planned (v1b) |

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

## OSV.dev and GitHub Security Advisories (planned)

KEV, NVD and EPSS describe **the CVE**, the vulnerability in the abstract. OSV and
GitHub describe **which package and which version** is affected, for Maven (Java)
and npm (Node.js). Not every package advisory has a CVE, so how to link both worlds
will be decided when v1b is planned.

## Keeping data fresh

Data is refreshed manually with `make ingest`. See
[Pages](pages.md) for the screens and the [Glossary](glossary.md) for the terms. How
each source is fetched, validated and stored is explained in
[technical ingestion](../technical/ingestion.md).

## A note on trust

Data from these sources is shown as received. The app never invents or fills in
technical details: if a source does not provide a value, it is shown as "Not
available".
