---
title: CVE
summary: The public identifier of a known vulnerability, such as CVE-2021-44228.
order: 10
keywords: cve, common vulnerabilities and exposures, identifier, id, cve id, number, reserved, rejected, vulnerability name
---

## What it is

A **CVE** (Common Vulnerabilities and Exposures) is a **name** for one specific vulnerability, so that everyone can talk about the same thing:
vendors, scanners, advisories, news and this app. It is an identifier plus a short public record, not a score or a verdict.

## Anatomy of an ID

```
CVE-2021-44228
 |    |    |
 |    |    +-- sequence number (4 or more digits)
 |    +------- year the ID was assigned (not when the bug was found or made public)
 +------------ fixed prefix
```

The sequence number is just a counter. A high number does not mean a worse flaw, and the year can be earlier than the day the
details became public (an ID can be reserved first and published later).

## Lifecycle

1. A **CNA** (see [CNA and ADP](/docs/concepts/cna-adp)) reserves an ID: state *Reserved*.
2. When the fix or the disclosure is ready, it writes the record: state *Published*.
3. Other organizations can add data ([NVD](/docs/sources/nvd) scores, [CISA](/docs/sources/cisa-vulnrichment) decisions).
4. If it turns out to be a duplicate or not a vulnerability, it becomes *Rejected*. It is not deleted.

## Example

`CVE-2021-44228` is the flaw known as **Log4Shell**: Apache Log4j2 would look up and run remote content named in log messages.
The CVE is the identifier; "Log4Shell" is a nickname. The CVE record says what it is, the other sources say how severe it
is, whether it is exploited and which versions are affected.

## Common mistakes

- **A CVE is not a severity.** For that, see [CVSS](/docs/concepts/cvss).
- **Not every vulnerability has a CVE.** Many package flaws only have a GitHub advisory id. See [Package advisories](/docs/concepts/package-advisories).
- **One flaw can get several CVEs** (when it is fixed in pieces) and one CVE can cover several products.
- **Names like Log4Shell or Heartbleed are not part of the system.** Search by the CVE id.

## Keep investigating

- [CVE.org](/docs/sources/cve-org), where the record lives
- [How to read a CVE](/docs/concepts/reading-a-cve), step by step with a real example
