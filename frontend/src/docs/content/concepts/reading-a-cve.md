---
title: How to read a CVE
summary: A step-by-step walkthrough of a real CVE (Log4Shell) using the fields of this app.
order: 130
keywords: walkthrough, tutorial, log4shell, how to read, guide, example, steps, triage, cve-2021-44228
---

## What it is

A worked example: the CVE page of **Log4Shell** (`CVE-2021-44228`), in the order that is useful when you are deciding what to do.

## Example: Log4Shell step by step

**1. Identify it.** `CVE-2021-44228`, in Apache Log4j2. The [CVE](/docs/concepts/cve) is only the name. The title and description
say what it is: a remote code execution flaw by log message lookups (JNDI).

**2. Is it being attacked?** The [KEV](/docs/concepts/kev) flag is *yes*, it was added on 2021-12-10, and the ransomware flag is *Known*. That settles it: this is
not theoretical.

**3. Will it keep being attacked?** [EPSS](/docs/concepts/epss) is near 100%. The attacks are continuous.

**4. How bad is it?** [CVSS](/docs/concepts/cvss) 10.0, Critical. In the vector `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` you can read: remote (`AV:N`), easy
(`AC:L`), no login (`PR:N`), no user action (`UI:N`), full impact (`C:H/I:H/A:H`). See [CVSS vector](/docs/concepts/cvss-vector).

**5. What kind of mistake is it?** The [CWE](/docs/concepts/cwe) list includes unsafe deserialization and expression-language injection: untrusted input ends
up being interpreted.

**6. Am I affected?** On the package advisory (`GHSA-jfh8-c2jp-5v3q`) look at the package `org.apache.logging.log4j:log4j-core` and
the [ranges](/docs/concepts/version-ranges). The first fix is `2.15.0`.

**7. Is the fix enough?** Check the references. For Log4Shell, 2.15.0 was followed by further CVEs (`CVE-2021-45046`, `CVE-2021-45105`) that needed later versions.
Always look at the newest advisory for the package.

**8. Where does it come from?** Each block says its [source](/docs/sources/cisa-kev) and when it was retrieved; if two sources
differ (for example two CVSS scores), both are right about *their* view.

## Common mistakes

- **Stopping at the score.** The score said "bad"; KEV and EPSS said "bad and happening".
- **Not checking the fixed version.** "Patched" can mean different versions on different release lines.
- **Trusting one source.** Each one answers one question; compare them. See [Severity is not priority](/docs/concepts/prioritizing).

## Keep investigating

- Try it in **Investigations** with `CVE-2021-44228`, and save a report with your notes.
- The **Sources** topics in the side menu explain where each field comes from.
