---
title: OSV.dev
summary: A database of vulnerabilities in open source packages, with the exact affected and fixed versions.
order: 40
keywords: osv, open source vulnerabilities, google, openssf, ecosystem, maven, npm, package, purl, affected versions, fixed, aliases, schema
---

CVE tells you a vulnerability exists. **OSV tells you which package, in which ecosystem and which versions** are affected,
and which version fixes it. That is what you need when you look at your `pom.xml` or `package.json`.

## At a glance

| | |
|---|---|
| Website | [osv.dev](https://osv.dev/) |
| Maintained by | Google runs the osv.dev service. The record format (the OSV schema) is an open specification hosted by the OpenSSF |
| What it provides | Vulnerability records for open source packages, from many databases, in one common format |
| Coverage | Dozens of ecosystems, including Maven (Java) and npm (Node.js) |

## What it tells you

OSV is an **aggregator**: GitHub's advisories, language-specific databases (PyPI, RustSec, Go) and others publish their records in
the OSV format, and osv.dev gathers them. Each record has:

- an **id** with a prefix that shows who published it: `GHSA-` (GitHub), `PYSEC-` (PyPI), `RUSTSEC-`, `GO-`, `MAL-` (malicious packages)...;
- **aliases**: ids of the same vulnerability elsewhere, usually a `CVE-` id;
- **affected packages**: ecosystem, package name and the affected versions as ranges;
- a summary, details, severity and references.

## Why not just use the CVE?

A CVE describes the vulnerability in general. OSV describes it **per package**. One CVE can affect several packages, and an
advisory can exist **without a CVE** (see [Package advisories](/docs/concepts/package-advisories)). The same package name can also exist in
different ecosystems (npm and PyPI both have a `zlib`), which is why OSV always pairs ecosystem and name.

## Example

A simplified record (the real one lists several ranges, one per release line):

```json
{
  "id": "GHSA-jfh8-c2jp-5v3q",
  "aliases": ["CVE-2021-44228"],
  "affected": [{
    "package": { "ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core" },
    "ranges": [{ "type": "ECOSYSTEM", "events": [{ "introduced": "2.13.0" }, { "fixed": "2.15.0" }] }]
  }]
}
```

Read the `events` in order: affected **from** `2.13.0` (introduced) **until** `2.15.0` (fixed, not affected). More in
[Affected and fixed versions](/docs/concepts/version-ranges). In Maven the package name is `groupId:artifactId`.

## How this app uses it

OSV is the single source of package advisories for **Maven and npm**: the app loads the GitHub advisories of those ecosystems through OSV. It shows the
affected package, the ranges as reported (introduced → fixed) and links the advisory to its CVE when there is one. Malicious-package
reports and withdrawn advisories are not included.

## Pitfalls

- **The app does not tell you if your version is affected.** Maven and npm order versions differently, so it only repeats the ranges.
- **Severity can be missing a score.** Often only the CVSS vector is present.
- **The same issue can appear under several ids.** Use `aliases` to connect them.

## Keep investigating

- [osv.dev](https://osv.dev/) and its [documentation](https://google.github.io/osv.dev/)
- [The OSV schema](https://ossf.github.io/osv-schema/), with every field
- Related here: [GitHub Advisories](/docs/sources/github-advisories), [Package advisories](/docs/concepts/package-advisories), [Affected and fixed versions](/docs/concepts/version-ranges)
