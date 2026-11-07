---
title: EPSS (FIRST)
summary: A daily estimate of how likely each CVE is to be exploited in the next 30 days.
order: 30
keywords: epss, first, exploit prediction scoring system, probability, percentile, empirical security, prediction, likelihood
---

EPSS answers a question CVSS does not: **will anyone actually attack this?** It is a statistical estimate, recalculated every day,
for every published CVE.

## At a glance

| | |
|---|---|
| Website | [first.org/epss](https://www.first.org/epss/) |
| Maintained by | The EPSS Special Interest Group of FIRST (Forum of Incident Response and Security Teams). The daily scores are produced by Empirical Security |
| What it provides | For each CVE: a probability (0 to 1) and a percentile |
| Updated | Daily, around 13:30 UTC |
| Current model | EPSS v5, published since 2026-06-15 (v4 was used from March 2025) |

## What it tells you

- **Probability** (`epss`): the estimated chance that exploitation activity for this CVE will be detected in the next 30 days. A score
  of `0.05` means 5%. It is based on observed exploitation reported by data partners (sensors, honeypots, intrusion detection, threat
  intelligence), not on confirmed successful attacks.
- **Percentile**: the share of all scored CVEs that have the same score or lower. It is a ranking, not a probability.

Both numbers matter. Most CVEs have a tiny probability, so the percentile tells you where a CVE stands among all of them.
In FIRST's words, the mean EPSS score is around 2.8% and the median around 0.7%. An EPSS of 10% looks small, yet it is far
above the typical CVE.

## What it does not tell you

- **Not severity.** EPSS does not measure how much damage a successful attack would do.
- **Not about you.** It knows nothing about your environment, exposure or protections.
- **Do not multiply EPSS by CVSS.** FIRST says explicitly that this does not give "probability × severity" and is never a good idea.
  The two scores are largely independent; use them side by side.
- **A KEV entry beats any EPSS value.** FIRST's guidance: if a CVE is in [KEV](/docs/sources/cisa-kev), treat it as actively
  exploited regardless of its EPSS score.

## Example

Take two made-up CVEs. One has CVSS 9.8 and EPSS 0.4%; the other has CVSS 6.5 and EPSS 85% (percentile 0.99). On paper the first
one is "critical", but the second one is much more likely to be attacked soon. EPSS helps to decide what to look at first.

## How this app uses it

EPSS is added to every KEV CVE, and to package advisories that have a CVE (if an advisory lists several CVEs, the highest
score is shown). It is shown as a percentage, and you can filter by a minimum EPSS. Scores are replaced on each run, so the
value you see is from the last time data was loaded, not necessarily from today.

## Pitfalls

- **It changes every day.** A score is a snapshot; compare it with care.
- **New CVEs start with little history**, so their first scores are less informative.
- **There is no official threshold** such as "above 0.1 is dangerous". Choose one based on how many CVEs you can handle.

## Keep investigating

- [EPSS home](https://www.first.org/epss/), [FAQ](https://www.first.org/epss/faq) and [how it works](https://www.first.org/epss/how-it-works)
- [Using EPSS](https://www.first.org/epss/using-epss), with guidance on thresholds
- Related here: [EPSS as a concept](/docs/concepts/epss), [Severity is not priority](/docs/concepts/prioritizing)
