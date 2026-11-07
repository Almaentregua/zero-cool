---
title: NVD
summary: NIST's database that adds severity scores, weakness types and affected products to CVE records.
order: 20
keywords: nvd, national vulnerability database, nist, cvss, enrichment, cpe, cwe, analyzed, awaiting analysis, deferred, status
---

The CVE program gives every vulnerability a name and a description. The **NVD** takes those records and adds the
details people use to triage them: a severity score, the type of weakness and the list of affected products.

## At a glance

| | |
|---|---|
| Website | [nvd.nist.gov](https://nvd.nist.gov/) (NIST's own page: [nist.gov/itl/nvd](https://www.nist.gov/itl/nvd)) |
| Maintained by | NIST, the US National Institute of Standards and Technology |
| What it provides | The CVE description and dates, [CVSS](/docs/concepts/cvss) scores and vectors, [CWE](/docs/concepts/cwe) weaknesses, [CPE](/docs/concepts/cpe) affected products and tagged references |
| Relationship with CVE | Built on top of the CVE list: NVD does not create CVE IDs, it enriches them |

## What it tells you

NVD "enriches" a CVE: it adds data the original record often does not have. The result for a CVE can include:

- a **CVSS score and vector** (older CVEs have version 2, most have 3.x, newer ones may have 4.0);
- the **CWE** that describes the kind of flaw;
- **CPE** entries naming the affected products and versions;
- **tags on the references** (for example "Patch" or "Vendor Advisory").

A CVE can show more than one rating: the one written by the CNA that assigned it and the one added by NIST.
They can differ, and both are legitimate. See [CVSS](/docs/concepts/cvss).

## How far along is a CVE: statuses

A CVE page in NVD has a status. The website names are below, with the API names in parentheses where they differ.

| Status | Meaning |
|---|---|
| Received | Recently published to the CVE list and now in NVD |
| Awaiting Enrichment (Awaiting Analysis) | Marked for NVD work, not started |
| Undergoing Enrichment (Undergoing Analysis) | NVD staff are working on it |
| Enriched (Analyzed) | Enrichment finished |
| Modified After Enrichment (Modified) | The record changed after enrichment; the NVD data may need amending |
| Not Scheduled (Deferred) | Not scheduled for enrichment: out of scope or not prioritized |
| Rejected | Rejected in the CVE list (decided by the CVE Program, not by NVD) |

NVD has changed these names before, so check [its status page](https://nvd.nist.gov/vuln/vulnerability-status) for the current ones.

## Not every CVE gets analyzed

Until 2026 NVD aimed to analyze every CVE. In April 2026, because of the growth in the number of CVEs, NIST
[announced](https://www.nist.gov/news-events/news/2026/04/nist-updates-nvd-operations-address-record-cve-growth) that it
would enrich only CVEs that meet certain criteria. The ones it prioritizes include:

- CVEs in [CISA KEV](/docs/sources/cisa-kev) (its goal is to enrich them within one business day);
- CVEs in software used within the US federal government;
- CVEs in critical software under Executive Order 14028.

The rest remain listed but are marked as lowest priority, and NIST no longer routinely adds its own severity score to them.
So for a recent, obscure CVE it is normal to see no NVD score at all.

## Example

For `CVE-2021-44228` (Log4Shell) NVD shows a CVSS 3.1 score of 10.0 (Critical), the weakness list (for example
`CWE-502`, deserialization of untrusted data, among others) and CPE entries for the affected Log4j versions. The CVE
record by itself has the description and the references.

## How this app uses it

NVD is fetched **only for CVEs that are in KEV**. It provides the official description (replacing CISA's short one),
the CVSS score and vector, the publication and modification dates and the reference links. When NVD has no score yet the
app shows "Not available"; it never estimates one. In *Investigations*, NVD is also queried live for any CVE.

## Pitfalls

- **No score does not mean low risk.** It often means "not analyzed yet".
- **Scores are not priority.** A 9.8 that nobody exploits can matter less than a 7.5 in KEV. See [Severity is not priority](/docs/concepts/prioritizing).
- **CPE data is imperfect.** Matching your exact product and version to CPE entries can give false positives and
  false negatives.

## Keep investigating

- [NVD home](https://nvd.nist.gov/) and [vulnerability statuses](https://nvd.nist.gov/vuln/vulnerability-status)
- [NIST's April 2026 announcement](https://www.nist.gov/news-events/news/2026/04/nist-updates-nvd-operations-address-record-cve-growth)
- Related here: [CVSS](/docs/concepts/cvss), [CWE](/docs/concepts/cwe), [CPE](/docs/concepts/cpe), [CVE.org](/docs/sources/cve-org)
