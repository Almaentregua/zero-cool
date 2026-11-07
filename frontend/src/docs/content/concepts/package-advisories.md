---
title: Package advisories
summary: Security notices about a package (not about a CVE in general), with ids like GHSA-... and the versions affected and fixed.
order: 100
keywords: advisory, package, ghsa, osv, ecosystem, maven, npm, purl, dependency, transitive, groupid, artifactid, alias, pysec, fixed version
---

## What it is

A **package advisory** says that a library, as published in an ecosystem (Maven, npm, PyPI...), has a vulnerability, and **which versions are affected and
which fix it**. It is the practical view of a problem: not "a flaw exists in Log4j", but "`log4j-core` from 2.13.0 up to 2.15.0 is affected; update to 2.15.0".

## Advisory vs CVE

| | CVE | Package advisory |
|---|---|---|
| Describes | A vulnerability, in general | A vulnerability **in one package of an ecosystem** |
| Id | `CVE-2021-44228` | `GHSA-jfh8-c2jp-5v3q`, `PYSEC-...`, `RUSTSEC-...` |
| Versions | Sometimes as free text or CPE | Structured ranges with introduced and fixed versions |
| Required? | Not every advisory has one | Can exist with or without a CVE |

An advisory lists **aliases**: ids of the same issue elsewhere, usually the CVE. That is how the app links them.

## Ecosystems and package names

An **ecosystem** is the world a package lives in: Maven (Java), npm (Node.js). The package name only makes sense with its ecosystem:

- **Maven**: `groupId:artifactId`, for example `org.apache.logging.log4j:log4j-core`.
- **npm**: the package name, for example `lodash` or a scoped one such as `@angular/core`.

## Example

You depend on `log4j-core:2.14.1`. The advisory tells you it is in the affected range and that `2.15.0` fixes it. Because advisories are per package, the
same CVE can create separate advisories for `log4j-core` and for products that bundle it.

## Common mistakes

- **Only checking your direct dependencies.** A vulnerable library can arrive indirectly (a *transitive* dependency) through something you use.
- **Assuming "no CVE" means "not serious".** Many advisories never get a CVE.
- **Treating the fixed version as the only safe one.** Later versions are also fine, unless a later advisory says otherwise (Log4Shell needed follow-up fixes).

## Keep investigating

- [OSV.dev](/docs/sources/osv) and [GitHub Advisories](/docs/sources/github-advisories)
- [Affected and fixed versions](/docs/concepts/version-ranges)
