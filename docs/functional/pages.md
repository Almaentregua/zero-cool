# Pages

> Status: **available** (v1a). Open http://localhost:5173 after `make dev`.
> Package vulnerabilities from OSV and GitHub (v1b) are not included yet.

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

**How to use it:** type in the search box and/or set filters, then press
**Apply**. **Reset** clears everything. Click the **CVSS**, **EPSS** or **Date
added** header to sort; click again to reverse. Use **Previous / Next** to move
between pages. The address bar keeps your filters, so you can reload the page
or bookmark a search.

**Filters** (can be combined):
- Date added: from / to.
- Technology: e.g. `Java`.
- Vendor / product: e.g. vendor `apache`, product `log4j`.
- Severity: tick one or more levels, e.g. High and Critical.
- Minimum EPSS: e.g. `0.5` shows only those with 50% or more.
- Used in ransomware: yes.

**Search:** type a CVE ID (`CVE-2021-44228`) to go straight to it, or free text
(`log4j remote code`) to search titles and descriptions.

**Example:** technology `Java` + severity `Critical` + minimum EPSS `0.5`
returns critical Java vulnerabilities that are very likely to be exploited.

## Vulnerability detail

**How to open it:** click a CVE ID in the list (or go to `/cve/CVE-2021-44228`).
**← Back to list** returns to your previous search with the same filters.

**Problem it solves:** understand one vulnerability fully.

**What you see:** all fields from the list, plus the full description, CVSS
vector, affected products and versions, links to references and advisories,
and the KEV remediation due date.

External text is always shown as plain text for safety, and links are only
clickable when they start with `http` or `https`.

If the CVE is not in the database you see a message saying so.

## Keeping data fresh

Data is not updated automatically. Run `make ingest` to refresh it (the first
run takes about 20 minutes because of NVD's request limits; later runs are fast).

## What is available

| Page | Status |
|------|--------|
| List and detail with KEV, NVD and EPSS data | Available (v1a) |
| Package vulnerabilities for Maven and npm (OSV, GitHub) | Planned (v1b) |
