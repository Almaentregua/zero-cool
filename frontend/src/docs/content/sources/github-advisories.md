---
title: GitHub Advisories
summary: GitHub's curated database of security advisories for open source packages (GHSA ids).
order: 50
keywords: github, ghsa, advisory database, dependabot, reviewed, unreviewed, malware, moderate, security advisories
---

GitHub keeps its own database of vulnerabilities in open source packages. Its ids look like `GHSA-jfh8-c2jp-5v3q`. It is
the database behind Dependabot alerts.

## At a glance

| | |
|---|---|
| Website | [github.com/advisories](https://github.com/advisories) and the data repository [github/advisory-database](https://github.com/github/advisory-database) |
| Maintained by | GitHub, with an internal curation team |
| What it provides | Advisories for packages in ecosystems such as npm, Maven, PyPI and others, with severity, affected ranges and fixes |
| Format and license | JSON in the OSV format, licensed CC-BY 4.0 |

## What it tells you

Advisories come in three kinds:

- **Reviewed**: checked by GitHub, the ones that trigger Dependabot alerts.
- **Unreviewed**: published automatically from the NVD feed, with no package-level curation.
- **Malware**: reports of malicious packages (for example from the npm security team and the OpenSSF malicious packages repository).

They are created from several origins: advisories reported on GitHub itself (for example by a maintainer through a private report),
the NVD, ecosystem databases and community contributions.

**GHSA ids** have the form `GHSA-xxxx-xxxx-xxxx`, four lowercase characters from a restricted alphabet in each group.
The severity uses four levels from CVSS: Low, Medium (GitHub also says "Moderate"), High and Critical.

## Example

`GHSA-jfh8-c2jp-5v3q` is the advisory for Log4Shell in the Maven package `org.apache.logging.log4j:log4j-core`. It lists the
CVE as an alias, the affected range and the fixed version. If a library maintainer discovers a flaw, they can publish a GHSA
**before** a CVE exists, or never request one.

## How this app uses it

The app does not call GitHub: OSV republishes GitHub's advisories, so [OSV.dev](/docs/sources/osv) is the single way in. The app
keeps reviewed advisories for Maven and npm, shows GitHub's severity level (not a numeric score) and ignores malware reports and withdrawn advisories.

## Pitfalls

- **Not every GHSA has a CVE.** About 8% do not in this app's data, so they live in their own list.
- **Moderate vs Medium** is the same level with two names.
- **Fixed does not mean you are safe.** You still need to update to a version at or above the fix.

## Keep investigating

- [Browse the advisories](https://github.com/advisories) and [about the database](https://docs.github.com/en/code-security/security-advisories/working-with-global-security-advisories-from-the-github-advisory-database/about-the-github-advisory-database)
- Related here: [OSV.dev](/docs/sources/osv), [Package advisories](/docs/concepts/package-advisories), [CVSS](/docs/concepts/cvss)
