---
title: KEV and ransomware use
summary: What it means for a CVE to be in the Known Exploited Vulnerabilities catalog, and what the ransomware flag says.
order: 80
keywords: kev, known exploited vulnerabilities, exploited in the wild, ransomware, known, unknown, due date, active exploitation, cisa
---

## What it is

**KEV** is the catalog [CISA](/docs/sources/cisa-kev) keeps of CVEs with reliable evidence of **active exploitation in the wild**. Being in KEV is a yes/no
fact: someone has already attacked with this.

## What the fields mean

- **In KEV: yes** means exploitation has been confirmed. Treat it as the strongest signal to act, whatever the CVSS or EPSS.
- **Date added**: when CISA listed it.
- **Due date**: the deadline for US federal agencies. For others it is a hint about urgency, not an obligation.
- **Ransomware use**: `Known` means CISA is aware of use in ransomware campaigns (the app shows "Yes"). `Unknown` (shown as "No") means CISA has no information about it, which is
  **not** the same as "never used".

## Example

You filter the list by Java and "Used in ransomware". The result is a short list of Java-related flaws that are exploited and have been seen in ransomware
attacks. That is a good first batch to check against your dependencies.

## Common mistakes

- **Reading "not in KEV" as "safe".** KEV is only what CISA has confirmed and has a fix for.
- **Reading "in KEV" as "I am affected".** It means the flaw is being exploited somewhere; you still need to check your versions.
- **Assuming the date added is the date of the first attack.** It is the date of the listing.

## Keep investigating

- [CISA KEV as a source](/docs/sources/cisa-kev)
- [Severity is not priority](/docs/concepts/prioritizing)
