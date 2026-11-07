---
title: CISA KEV
summary: The catalog of vulnerabilities that are already being exploited in real attacks.
order: 10
keywords: kev, known exploited vulnerabilities, cisa, catalog, exploited in the wild, active exploitation, ransomware, bod 26-04, due date
---

KEV is a short list with one strong message: **someone is already attacking this vulnerability**. It does not
say how severe the flaw is, only that it is being used.

## At a glance

| | |
|---|---|
| Website | [cisa.gov/known-exploited-vulnerabilities-catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| Maintained by | CISA, the US Cybersecurity and Infrastructure Security Agency |
| What it provides | CVEs with confirmed exploitation, plus vendor, product, name, short description, date added, due date and ransomware flag |
| Formats | Web catalog, CSV and JSON |
| Size | Around 1,800 entries (a few thousand CVEs are published every year, so KEV is a small, high-signal subset) |

## What it tells you

A CVE is added to the catalog only when it meets three conditions, quoted from
[CISA's criteria page](https://www.cisa.gov/known-exploited-vulnerabilities):

1. It has an assigned [CVE](/docs/concepts/cve) ID.
2. There is reliable evidence of active exploitation in the wild.
3. There is a clear remediation action, such as a vendor update.

Some details that are easy to miss:

- **"Exploited" means a real attack**, including attempts. Scanning the internet, research on an exploit and public
  proof-of-concept code do not count by themselves, and a public proof of concept is not required.
- **Old CVEs can be added.** If a ten-year-old flaw starts being used again, it enters the list.
- **A CVE needs a clear fix** to be listed. A real attack on a flaw with no remediation can be absent for that reason.
- **Absence from KEV does not mean safe.** It means CISA has no confirmed report that meets these conditions yet.

## The fields of an entry

- **Vendor and product**: free text written by CISA, for example `Apache` / `Log4j2`.
- **Name and description**: a short, CISA-written summary (not the official CVE text).
- **Date added**: the day CISA listed it. It is the date of the listing, not of the first attack.
- **Due date**: the deadline for US federal civilian agencies to fix it. It is a useful sense of urgency for anyone,
  but it is a rule for agencies, not for you. See *Federal deadlines* below.
- **Known ransomware campaign use**: `Known` or `Unknown`. `Unknown` means CISA has no information, not that
  ransomware groups never used it.

## Example

`CVE-2021-44228` (Log4Shell) is in KEV. Its entry tells you that the flaw in Apache Log4j2 is being exploited and that
it has a vendor fix. To see how bad the flaw is you need [CVSS](/docs/concepts/cvss) (from [NVD](/docs/sources/nvd)); to
see whether attacks are likely to keep coming you can add [EPSS](/docs/concepts/epss). KEV, CVSS and EPSS answer
different questions, see [Severity is not priority](/docs/concepts/prioritizing).

## Federal deadlines

KEV started as the list behind a US government directive, BOD 22-01 (2021). In June 2026 CISA replaced it with
**BOD 26-04**, which keeps the catalog and says that the criteria for inclusion "remain unchanged". Under it, US federal
civilian agencies must remediate listed vulnerabilities within deadlines that depend on factors such as whether
the system is exposed to the internet. Nobody else is bound by those deadlines, but they are a reasonable hint of urgency.

## How this app uses it

KEV defines **which CVEs exist in the main list**: everything else (NVD, EPSS) is added on top of them. The app shows
vendor, product, date added, due date and the ransomware flag exactly as CISA publishes them, and lets you filter by technology
through the vendor and product names.

## Pitfalls

- KEV is **binary**. It cannot tell a minor flaw that is exploited from a critical one.
- It reflects **what CISA has confirmed**. It is biased toward products used by US organizations and toward flaws
  that have a vendor fix.
- Vendor and product are not normalized: the same product can appear under slightly different names.

## Keep investigating

- [KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and [its criteria](https://www.cisa.gov/known-exploited-vulnerabilities)
- [BOD 26-04](https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk), the current directive
- Related here: [KEV as a concept](/docs/concepts/kev), [EPSS](/docs/concepts/epss), [CVSS](/docs/concepts/cvss)
