---
title: MITRE CWE
summary: A catalog of the kinds of weaknesses in software and hardware that lead to vulnerabilities.
order: 80
keywords: cwe, mitre, common weakness enumeration, weakness, top 25, injection, xss, sql injection, deserialization, class, base, variant, pillar, view
---

A CVE is **one concrete vulnerability**. A CWE is **the kind of mistake** behind it. The CWE catalog gives those kinds of mistakes
a shared name and number.

## At a glance

| | |
|---|---|
| Website | [cwe.mitre.org](https://cwe.mitre.org/) |
| Maintained by | MITRE, with sponsorship from CISA (US DHS) |
| What it provides | Entries describing a type of weakness: name, description, how it happens, consequences and mitigations |
| Updated | Three to four times a year |

## What it tells you

Each entry has an id (`CWE-79`), a name and a level of abstraction:

- **Pillar** and **Class**: very general ideas ("improper input validation").
- **Base**: specific enough to detect and prevent, independent of technology. Most useful ones are here.
- **Variant**: tied to a certain kind of product or language.

Other entry types group them: **Category** or **Grouping** (related weaknesses) and **View** (a way of looking at the catalog).

## The CWE Top 25

Each year the CWE Program publishes the *Top 25 Most Dangerous Software Weaknesses*, a ranking built from the CVE records of the year.
It is a good guide to what to prevent first when writing code.

## Example

Three you will see all the time:

| CWE | Name | In plain words |
|---|---|---|
| CWE-79 | Cross-site Scripting (XSS) | The app puts untrusted input in a page without neutralizing it, so an attacker can run script in a victim's browser |
| CWE-89 | SQL Injection | Untrusted input becomes part of an SQL query and changes what it does |
| CWE-502 | Deserialization of Untrusted Data | The app rebuilds objects from data it does not control; it is behind many Java and PHP object-injection attacks |

## How this app uses it

CWE ids come from CVE records (the CNA's or CISA's); MITRE CWE then supplies the **name and definition**. *Investigations* shows who listed
each one (CNA, CISA or both). If MITRE has no such entry, the block shows the id without a name.

## Pitfalls

- **A CWE is not a vulnerability.** `CWE-79` does not say whether you are affected; it says what kind of flaw a CVE is.
- **Several CWEs can fit one CVE**, and different sources may choose different ones.
- **Some CVEs have no CWE**, or use generic ones such as `NVD-CWE-Other` (NVD's placeholder; not a MITRE entry).

## Keep investigating

- [CWE home](https://cwe.mitre.org/), [the Top 25](https://cwe.mitre.org/top25/) and, for example, [CWE-502](https://cwe.mitre.org/data/definitions/502.html)
- Related here: [CWE as a concept](/docs/concepts/cwe), [CVE](/docs/concepts/cve), [NVD](/docs/sources/nvd)
