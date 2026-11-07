---
title: CPE
summary: A standard text string that names a product and version, used to say what is affected.
order: 60
keywords: cpe, common platform enumeration, product, vendor, version, applicability, cpe 2.3, wildcard, purl, package url, affected products
---

## What it is

**CPE** (Common Platform Enumeration) is a naming scheme for software, operating systems and hardware. It is how
[NVD](/docs/sources/nvd) says *which products are affected* in a way a program can match. CPE is maintained by NIST.

## Format

CPE 2.3 uses a string of fields separated by colons:

```
cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*
        | |      |     |
        | |      |     +-- version
        | |      +-------- product
        | +--------------- vendor
        +----------------- part: a = application, o = operating system, h = hardware
```

The remaining fields (update, edition, language, ...) are usually `*`, which means "any". A `-` means "not applicable".

## Version ranges

NVD rarely lists one CPE per affected version. It writes a **range** on a CPE, such as *from 2.0 (included) up to 2.15.0 (excluded)*, and
a CVE can combine several, even with "and" conditions (for example, the product running on a certain operating system).

## Example

`cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*` with a range up to `2.15.0` means "Apache Log4j, any version below 2.15.0". A scanner compares what it finds
in your system with these entries.

## CPE and package names

CPE is built for products in general and is a weak fit for libraries: vendor and product names are free to choose, so matching has false
positives and false negatives. For packages, [OSV](/docs/sources/osv) uses the ecosystem and package name, and optionally a
**purl** (Package URL), which looks like `pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1`. See [Package advisories](/docs/concepts/package-advisories).

## Common mistakes

- **Treating CPE data as exact.** It can be missing, outdated or too broad.
- **Confusing vendor and product spelling.** `apache` vs `apache_software_foundation` are different strings.
- **Expecting CPE in every CVE.** CISA no longer adds CPE data, and NVD may not have enriched the record.

## Keep investigating

- [NIST's CPE page](https://csrc.nist.gov/projects/security-content-automation-protocol/specifications/cpe)
- [Package URL (purl) specification](https://github.com/package-url/purl-spec)
