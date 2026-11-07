---
title: CISA Vulnrichment
summary: CISA's additions to CVE records: an SSVC decision, and sometimes CVSS and weaknesses.
order: 70
keywords: vulnrichment, cisa, ssvc, adp, exploitation, automatable, technical impact, enrichment, coordinator
---

Vulnrichment is CISA's effort to add practical context to CVE records, so that a CVE says more than "this exists".

## At a glance

| | |
|---|---|
| Website | [github.com/cisagov/vulnrichment](https://github.com/cisagov/vulnrichment) |
| Maintained by | CISA, as an ADP (Authorized Data Publisher) of the CVE Program |
| What it provides | An **SSVC** decision, and for some CVEs also CVSS and CWE; it marks CVEs that are in KEV |
| Where it lives | A public GitHub repository; the results are also pushed back into the CVE records |

## What it tells you

The main addition is the [SSVC](/docs/concepts/ssvc) decision, with three points:

| Decision point | Values | Question |
|---|---|---|
| Exploitation | none, public proof of concept (`poc`), active | Is it being exploited? |
| Automatable | yes, no | Can an attacker automate it at scale? |
| Technical impact | partial, total | How much control does the attacker get? |

For higher-risk CVEs CISA can also add a CVSS score and CWE ids, "where there is enough supporting evidence". CISA stopped adding CPE
strings on 10 December 2024. **CISA never overwrites the data of the CNA**: its additions are a separate block.

## Example

A CVE with *exploitation: active*, *automatable: yes* and *technical impact: total* is the worst combination: it is being
attacked, the attack can be scripted and the attacker gets full control. Compare it with *none / no / partial*.

## How this app uses it

Only **Investigations** reads it, live. CISA's values are shown in their own block, apart from the CNA's and NVD's.
When CISA has not enriched a CVE, the block says "no data".

## Pitfalls

- **Not every CVE is enriched.** CISA focuses on new and higher-risk CVEs. Missing data means "not assessed".
- **The decision is CISA's view**, built for its own audience (the "Coordinator" decision tree), not a verdict for your organization.

## Keep investigating

- [Vulnrichment repository](https://github.com/cisagov/vulnrichment)
- Related here: [SSVC](/docs/concepts/ssvc), [CNA and ADP](/docs/concepts/cna-adp), [CVE.org](/docs/sources/cve-org), [CISA KEV](/docs/sources/cisa-kev)
