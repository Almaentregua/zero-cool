---
title: CVSS
summary: The 0 to 10 score that describes how technically severe a vulnerability is.
order: 30
keywords: cvss, common vulnerability scoring system, score, severity, critical, high, medium, low, base score, 3.1, 4.0, version 2, rating, none
---

## What it is

**CVSS** (Common Vulnerability Scoring System) is a standard from [FIRST](https://www.first.org/cvss/) that turns a description of a flaw into a
**number from 0.0 to 10.0**. The number comes from a set of answers (how is it attacked, what is needed, what is lost) written as a
[vector](/docs/concepts/cvss-vector). Same vector, same score, in any tool.

CVSS measures **how bad the flaw is in the abstract**. It does not say whether anyone is attacking it
([EPSS](/docs/concepts/epss), [KEV](/docs/concepts/kev)) or what it means in your system.

## Severity levels

```diagram
severity-scale
```

| Score | Severity (CVSS 3.x and 4.0) |
|---|---|
| 0.0 | None |
| 0.1 – 3.9 | Low |
| 4.0 – 6.9 | Medium |
| 7.0 – 8.9 | High |
| 9.0 – 10.0 | Critical |

CVSS v2 has no *None* or *Critical* level: it only had Low, Medium and High.

## Versions

You will see several, because old CVEs keep their old score:

- **v2** (2007): old; scores of CVEs from before about 2016.
- **v3.0 / v3.1** (3.1 from 2019): the most common today.
- **v4.0** (November 2023): the newest. It adds *Attack Requirements* and splits the impact into the vulnerable system and the
  "subsequent" ones. Adoption is still partial.

The versions are **not comparable**: a 7.5 in v2 and a 7.5 in v3.1 are not the same thing. The app shows the newest one available.

## Base, Threat and Environmental

What the CVE databases publish is almost always the **Base score** (the flaw itself, always true). CVSS also allows adjusting it with
**Threat** metrics (for example, is there an exploit?) and **Environmental** ones (how important is the affected system for you). In v4.0 the name tells
what was used: `CVSS-B` is base only, `CVSS-BT` adds threat, `CVSS-BE` environment and `CVSS-BTE` both. If a score does not say, assume base.

## Example

Log4Shell has base score **10.0 (Critical)**: it can be attacked over the network, with no login, no user action, and it gives full control.
Another CVE with 9.8 differs only by one detail of the vector. A CVE with 5.3 might only leak a little information.
Both could be in [KEV](/docs/sources/cisa-kev) or not; the score alone does not tell you.

## Common mistakes

- **High score is not "will be attacked".** Most 9.8 CVEs are never exploited.
- **Low score is not "ignore".** A medium flaw that is exploited in the wild can matter more.
- **Several scores for one CVE.** The CNA and NVD can score differently (different reading of the same facts, or different versions).
  The app shows what each source says.
- **No score** often means "not scored yet" (see [NVD](/docs/sources/nvd)).

## Keep investigating

- [How to read a CVSS vector](/docs/concepts/cvss-vector)
- [FIRST CVSS](https://www.first.org/cvss/), with the specifications and calculators
- [Severity is not priority](/docs/concepts/prioritizing)
