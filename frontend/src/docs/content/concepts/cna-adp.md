---
title: CNA and ADP
summary: Who writes a CVE record (the CNA) and who adds to it afterwards (an ADP).
order: 20
keywords: cna, adp, cve numbering authority, authorized data publisher, cisa-adp, vendor, assigner, root, cna of last resort
---

## What they are

- **CNA** (CVE Numbering Authority): an organization authorized by the CVE Program to assign CVE IDs and write the records for the
  vulnerabilities in its scope. There are hundreds: software vendors, open source projects, security researchers' firms, national CERTs.
- **ADP** (Authorized Data Publisher): an organization allowed to **add** information to a record that someone else created, without
  changing the CNA's part. CISA is one (its additions are [Vulnrichment](/docs/sources/cisa-vulnrichment)).

Why it matters: a CVE record has **containers**, one per author. You can see who said what: the CNA's container, CISA's container and so on.

## Example

For `CVE-2021-44228` the CNA is the Apache Software Foundation, the maker of Log4j. It wrote the description and the first
rating. Later, CISA as ADP added its own decision data. [NVD](/docs/sources/nvd) is a separate database built on top of the records: its data
lives in NVD, not inside the CVE record.

## Common mistakes

- **A rating is not neutral.** The CNA's severity is the vendor's opinion; NVD's or CISA's can differ.
- **Quality varies.** A CNA that is a small project may write a short record without a vector or a weakness.
- **Do not confuse ADP with NVD.** Both "add data", but ADP data is inside the CVE record and NVD's is in NVD.

## Keep investigating

- [CVE.org](/docs/sources/cve-org) and its list of CNAs
- [CISA Vulnrichment](/docs/sources/cisa-vulnrichment)
