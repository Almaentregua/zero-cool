---
title: CWE
summary: The catalog of weakness types behind vulnerabilities, such as XSS, SQL injection or unsafe deserialization.
order: 50
keywords: cwe, common weakness enumeration, weakness, flaw type, owasp, injection, xss, sql injection, deserialization, top 25, category, class, base, variant, nvd-cwe-other, nvd-cwe-noinfo
---

## What it is

A **CWE** (Common Weakness Enumeration) is a numbered **type of mistake** in software or hardware design. It is maintained by
[MITRE](/docs/sources/mitre-cwe).

The relation with CVE is simple:

- A **CWE** is the *kind of mistake* (SQL injection).
- A **CVE** is *one case* of it in one product (SQL injection in the login page of product X, version Y).

```diagram
cve-cwe-cpe
```

## Why it is useful

- It tells you **what kind of problem** this is without reading the details, so it helps to spot patterns ("many of our CVEs are deserialization").
- It points to the **fix pattern**: CWE entries list typical mitigations.
- It is the language of secure-coding guidance, such as the annual *CWE Top 25*.

## Example

| CWE | Name | One-line idea |
|---|---|---|
| CWE-79 | Cross-site Scripting | Untrusted input shown in a page and run as script by the browser |
| CWE-89 | SQL Injection | Untrusted input changes the meaning of a database query |
| CWE-502 | Deserialization of Untrusted Data | Rebuilding objects from data an attacker controls |
| CWE-917 | Expression Language Injection | Untrusted input evaluated as an expression |

NVD lists several CWEs for Log4Shell, among them CWE-502 and CWE-917. Several can fit because the flaw has more than one root cause.

## How specific is a CWE?

Entries have levels: **Pillar** and **Class** are very broad ("improper input validation"), **Base** is specific and the most useful,
**Variant** is tied to a technology. Groupings such as categories and views collect related ones. When you have the choice, the more specific
the better; a broad CWE tells you little.

## Common mistakes

- **CWE does not say if you are affected.** It names the type of flaw only.
- **Do not expect one CWE per CVE.** There can be several, from different sources (CNA, CISA, NVD), or none.
- **`NVD-CWE-Other` and `NVD-CWE-noinfo`** are NVD placeholders, not real MITRE entries.

## Keep investigating

- [CWE home](https://cwe.mitre.org/) and the [Top 25](https://cwe.mitre.org/top25/)
- [MITRE CWE as a source](/docs/sources/mitre-cwe)
