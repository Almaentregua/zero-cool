---
title: Severity is not priority
summary: How to combine CVSS, EPSS, KEV and your own context to decide what to fix first.
order: 120
keywords: prioritization, priority, risk, triage, severity, cvss, epss, kev, ssvc, exposure, reachability, patch, what to fix first
---

## The idea

Each signal answers a different question. None of them is "risk" by itself:

| Signal | Question it answers | Strength | Blind spot |
|---|---|---|---|
| [**KEV**](/docs/concepts/kev) | Is it already being exploited? | The strongest sign to act | Only confirmed cases; no severity |
| [**EPSS**](/docs/concepts/epss) | Will it be exploited soon? | Separates the few likely from the many unlikely | A statistic; changes daily |
| [**CVSS**](/docs/concepts/cvss) | How much damage could it do? | Shows impact and how easy it is | Says nothing about real attacks |
| [**SSVC**](/docs/concepts/ssvc) | What does CISA suggest? | Combines exploitation and impact | Only for CVEs CISA enriched |
| **Your context** | Do I use it? Is it exposed? | The only one about *you* | Nobody can calculate it for you |

## A reading order

1. **Do I use the affected product and version?** If not, stop. See [affected versions](/docs/concepts/version-ranges).
2. **Is it in KEV?** If yes, it goes first.
3. **EPSS high?** (over a few percent, or in a high percentile) it is a candidate even without a KEV entry.
4. **CVSS and vector:** is it remote, with no login (`AV:N/PR:N`) and with high impact? Check the [vector](/docs/concepts/cvss-vector), not only the number.
5. **Exposure:** is the component reachable from the Internet or from untrusted input?
6. **Is there a fix?** If not, look for mitigations in the references.

## Example

| CVE | CVSS | EPSS | KEV | Reading |
|---|---|---|---|---|
| A | 9.8 | 0.2% | no | Severe on paper, not expected to be attacked. Plan it |
| B | 6.5 | 70% | no | Medium score but very likely to be attacked. Look at it soon |
| C | 7.5 | 12% | yes | Being exploited. First |

(These are made-up numbers to show the logic.)

## Common mistakes

- **Sorting only by CVSS.** It puts many unattacked flaws before the few that matter.
- **Ignoring Low/Medium.** They can be chained with others or be exploited.
- **Using a fixed rule forever.** The numbers change: EPSS daily, KEV when new entries arrive.

## Keep investigating

- [FIRST: using EPSS](https://www.first.org/epss/using-epss)
- [How to read a CVE](/docs/concepts/reading-a-cve)
