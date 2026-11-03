# Pages

> Status: **planned** (v1). The data and the API behind these pages are already
> available (see `docs/technical/api.md`); the screens are not built yet.
> Examples show the intended behavior.

## Vulnerability list

**Problem it solves:** see in one place which vulnerabilities matter, instead
of checking several websites.

**What you see:** a table with one row per vulnerability.

| Field | Meaning |
|-------|---------|
| CVE ID | Public identifier, e.g. `CVE-2021-44228` |
| Title / description | Short summary |
| Severity (CVSS) | Score from 0 to 10 and its level (Low, Medium, High, Critical) |
| EPSS | Probability (0-100%) that it will be exploited soon |
| Actively exploited (KEV) | Yes if attackers are already using it |
| Used in ransomware | Yes if known to be used in ransomware campaigns |
| Date added | When it entered the catalog |
| Technologies | Related technologies, e.g. Java, Node.js |

Any value we do not have is shown as "not available". Nothing is guessed.

**Filters** (can be combined):
- Date added: from / to.
- Technology: e.g. `Java`.
- Vendor / product: e.g. vendor `apache`, product `log4j`.
- Severity: e.g. only High and Critical.
- Minimum EPSS: e.g. `0.5` shows only those with 50% or more.
- Used in ransomware: yes.

**Search:** type a CVE ID (`CVE-2021-44228`) to go straight to it, or free text
(`log4j remote code`) to search titles and descriptions.

**Example:** technology `Java` + severity `Critical` + minimum EPSS `0.5`
returns critical Java vulnerabilities that are very likely to be exploited.

## Vulnerability detail

**Problem it solves:** understand one vulnerability fully.

**What you see:** all fields from the list, plus the full description, CVSS
vector, affected products and versions, links to references and advisories,
and which sources reported it (CISA KEV, NVD, EPSS, OSV, GitHub).

External text is always shown as plain text for safety.

## Keeping data fresh

Data is not updated automatically. Run `make ingest` to refresh it (the first
run takes about 20 minutes because of NVD's request limits; later runs are fast).

## Planned availability

| Page | Version |
|------|---------|
| List and detail with KEV, NVD and EPSS data | v1a |
| Package vulnerabilities for Maven and npm (OSV, GitHub) | v1b |
