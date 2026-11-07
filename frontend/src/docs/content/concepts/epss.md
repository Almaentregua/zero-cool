---
title: EPSS
summary: How to read the exploitation probability and its percentile.
order: 70
keywords: epss, probability, percentile, exploit prediction scoring system, likelihood, 30 days, score, exploitation
---

## What it is

**EPSS** (Exploit Prediction Scoring System) estimates how likely it is that a CVE will see exploitation activity **in the next 30 days**. It
is calculated daily for every CVE by [FIRST](/docs/sources/epss) from data such as available exploit code, vulnerability traits and reports of attacks.

## The two numbers

- **Probability**, from 0 to 1 (the app shows it as %). `0.05` is a 5% estimated chance.
- **Percentile**: the share of all CVEs with an equal or lower score. A percentile of `0.9` means it ranks above 90% of CVEs.

Why both: the scores are very skewed. Most CVEs are around 1% or less, so even 10% is high. FIRST places 0.10 around the 95th percentile.

## How to read it

| Probability | Reading |
|---|---|
| Under 1% | Typical CVE; the attack is not expected soon |
| 1% to 10% | Worth noticing; above most CVEs |
| Over 10% | Rare and high; attackers are likely already interested |

These cut-offs are only a rule of thumb for reading; FIRST has no official bands.

## Example

`CVE-2021-44228` (Log4Shell) has an EPSS near 100%: it is exploited constantly. A CVE with CVSS 9.8 and EPSS 0.3% is severe on paper,
but rarely attacked in practice.

## Common mistakes

- **Treating it as a fact.** It is a statistic, and it changes every day.
- **Multiplying it by CVSS.** FIRST warns that this does not produce "risk".
- **Ignoring KEV because EPSS is low.** If a CVE is in [KEV](/docs/concepts/kev), it is exploited, whatever EPSS says.
- **Reading it as severity.** A 90% EPSS on a flaw that leaks a bit of information is still low impact.

## Keep investigating

- [FIRST: EPSS FAQ](https://www.first.org/epss/faq) and [using EPSS](https://www.first.org/epss/using-epss)
- [Severity is not priority](/docs/concepts/prioritizing)
