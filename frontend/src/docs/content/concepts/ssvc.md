---
title: SSVC
summary: CISA's decision method: three questions that turn a CVE into an action.
order: 90
keywords: ssvc, stakeholder-specific vulnerability categorization, decision tree, exploitation, automatable, technical impact, poc, track, attend, act, cisa coordinator
---

## What it is

**SSVC** (Stakeholder-Specific Vulnerability Categorization) is a method, originally from Carnegie Mellon's SEI, that avoids a single number. It asks a few
questions in order and ends in a **decision** (what to do). [CISA](/docs/sources/cisa-vulnrichment) publishes the answers for some CVEs.

## The three decision points shown here

| Question | Values | Meaning |
|---|---|---|
| **Exploitation** | none, public proof of concept, active | Is there an attack, or at least public code? |
| **Automatable** | yes, no | Could an attacker script the attack at scale, with no manual work for each victim? |
| **Technical impact** | partial, total | How much control or data does the attacker get? |

A vulnerability that is exploited, automatable and with total impact is the worst case. In CISA's decision tree such combinations end in the highest-urgency
outcome (the guide's outcomes go from *Track* to *Act*, with *Track\** and *Attend* in between).

## Example

| Exploitation | Automatable | Technical impact | Reading |
|---|---|---|---|
| active | yes | total | Urgent: being attacked, easy to scale, full compromise |
| none | no | partial | Low urgency: no attacks, needs manual work, limited reach |

## Common mistakes

- **Treating it as your decision.** CISA's tree is built for its own use. A decision for your organization needs your context (exposure, importance).
- **Expecting it on every CVE.** Only the CVEs CISA enriched have it.
- **Confusing it with CVSS.** SSVC is a categorical decision, not a score.

## Keep investigating

- [CISA Vulnrichment](/docs/sources/cisa-vulnrichment)
- [CISA's SSVC guide](https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc)
- [Severity is not priority](/docs/concepts/prioritizing)
