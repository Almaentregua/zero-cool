# Pages

> Status: **available** (v1a and v1b). Open http://localhost:5173 after `make dev`.
> The top menu switches between **Known exploited (KEV)**, **Package advisories**, **Investigations**, **Reports** and **Docs**.

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

## Package advisories

**Problem it solves:** find out whether the libraries you use (Java/Maven, Node.js/npm)
have known security problems, and which version fixes them.

**What you see:** a table with one row per advisory (open it from the **Package
advisories** menu).

| Field | Meaning |
|-------|---------|
| Advisory | The advisory id, for example `GHSA-jfh8-c2jp-5v3q` |
| Summary | Short description |
| Severity | Low, Medium, High or Critical, as rated by GitHub |
| EPSS | Probability of exploitation, from the CVE; with several CVEs, the highest |
| CVE | The related CVE ids (some advisories have none) |
| Packages | Affected packages, with their ecosystem (Maven or npm) |
| Published | Publication date |

**Filters** (can be combined, applied with **Apply**): technology, package name (part of the
name is enough), severity (one or more), minimum EPSS, publication dates, and whether the
advisory has a CVE. The search box looks in the advisory id, summary, CVE ids and package
names. Click **EPSS** or **Published** to sort.

**Example:** technology `Java` + severity `Critical` + minimum EPSS `0.9` shows critical
Java library problems that are very likely to be exploited.

**Advisory detail:** click an advisory id. You see the affected packages with the versions
affected and the versions that fix it, the CVE ids (each one is a link when that CVE is in
the Known exploited list), the full description and the references.

Important: the affected version ranges are shown exactly as the source reports them. The
app does **not** tell you whether the version you use is affected, and it does not show
malicious-package reports or withdrawn advisories.

**From a CVE to its packages:** the detail page of a Known exploited CVE has an **Affected
packages** section listing the advisories that mention it (most CVEs have none, because many
are about products that are not Maven or npm packages).

## Keeping data fresh

Data is not updated automatically. Run `make ingest` to refresh it (the first
run takes about 20 minutes because of NVD's request limits; later runs are fast).

## What is available

| Page | Status |
|------|--------|
| List and detail with KEV, NVD and EPSS data | Available (v1a) |
| Package advisories for Maven and npm (OSV, GitHub) | Available (v1b) |

## Investigations

**Problem it solves:** when one vulnerability matters to you, gather everything known about it
without opening a dozen websites, and see exactly where each fact comes from.

**How to use it:** open **Investigations**, type one or more CVE ids (separated by spaces or
commas, up to 10) and press **Investigate**. It works for any CVE, whether it is in the KEV
catalog or not. It can take several seconds because every source is asked. **Refresh from the
sources** asks them again instead of reusing recent answers.

**What you see:** for each CVE, first a list of **Sources consulted** with the result of each
one, then one block per source:

| Source | What it tells you |
|--------|-------------------|
| CISA KEV | Whether attackers are known to exploit it, since when, and ransomware use. "No" is an answer too |
| NVD (NIST) | Official description, CVSS score and vector, dates and links |
| EPSS (FIRST) | Probability that it will be exploited in the next 30 days |
| OSV / GitHub Advisories | Maven and npm packages affected and the versions that fix it |
| CVE.org (CNA record) | What the organization that assigned the CVE published: description, weaknesses, affected products |
| CISA Vulnrichment | CISA's own assessment: SSVC decision (exploitation, automatable, technical impact), CVSS and weaknesses |
| MITRE CWE | What each weakness type listed for the CVE means |

Every block shows the **source**, a link to where the data comes from, **when it was retrieved**
and its **status**: *Has data*, *No data* (the source was asked and has nothing; the reason is
given) or *Error* (the source could not be reached; the others are not affected). Values from
different sources are never merged: if NVD and CISA rate it differently, you see both.
Anything missing is shown as "not available".

**Example:** type `CVE-2021-44228` and press Investigate. You see it is in KEV with a CVSS of
10.0, that CISA marks exploitation as *active*, that its weakness is CWE-502 (deserialization of
untrusted data), and which Maven packages fix it.

**Keeping it:** below the search box, **Save as report** stores what every source said right now
under a title you choose (optional). It opens the new report.

## Reports

**Problem it solves:** pick up an investigation later, with your notes and the evidence as you left it.

**The list** (menu **Reports**) shows your saved reports, the most recently updated first.

**Opening a report** shows:
- Its **notes**, written by you. Press **Edit notes** to change them; there is a preview while you
  type. Notes accept Markdown (headings, lists, bold, links, code). Choose **Markdown** or **Plain text**
  to decide how they are shown; Plain text shows exactly what you typed. Your choice is remembered in
  this browser and changing it never alters the notes. For safety, raw HTML in notes is ignored, only
  web links (http/https) are clickable and images are not loaded.
- The **CVEs** in the report. You can add more (**Add and investigate**) or remove them; a report keeps
  between 1 and 10.
- For each CVE, the same **sources consulted** list and **one block per source** as in Investigations, with
  the source, its link, when it was retrieved and its status. This is a **saved snapshot**: it shows what
  the sources said when the data was retrieved.

**Buttons:**
| Button | What it does |
|--------|--------------|
| Refresh from the sources | Asks every source again and lists **what changed** (new data, a source that now has or lost data, fields that changed). If a source fails during a refresh, its previous data is kept and the list says so |
| Rename | Changes the title |
| Mark as done / Reopen | Marks the investigation as finished or active again |
| Delete | Deletes the report after asking for confirmation. It cannot be undone |

There are no user accounts in this version: anyone who can open the app sees and edits all reports.

## Docs

**Problem it solves:** understand the security terms and data sources behind the numbers, without leaving the app. It is written
for developers who are not security specialists: technical, but short, with examples and links to keep learning.

**How to use it** (menu **Docs**):
- The side list groups the topics into **Sources** and **Concepts**. On a small screen the list can be collapsed.
- The **search box** looks in titles, related words and the text of every topic, and shows where the words were found. Every word you type
  must appear in the topic. Example: `deserialization` finds *CWE*; `ransomware` finds *CISA KEV* and *KEV and ransomware use*.
- Each topic starts with a short summary and a list of its sections. The last section, **Keep investigating**, links to the official pages
  and to related topics.
- Next to many terms in the other pages (CVSS, EPSS, KEV, CVSS vector, ecosystems, fixed versions, the name of each source in an
  investigation) there is a small **?** that opens the matching topic.

**What each group has:**
| Group | Topics |
|-------|--------|
| Sources | CISA KEV, NVD, EPSS (FIRST), OSV.dev, GitHub Advisories, CVE.org, CISA Vulnrichment, MITRE CWE. Each one says its website, who runs it, what it provides, an example, how this app uses it and its common pitfalls |
| Concepts | CVE, CNA and ADP, CVSS, CVSS vector (with an interactive breakdown), CWE, CPE, EPSS, KEV and ransomware use, SSVC, package advisories, affected and fixed versions, "severity is not priority" and a step-by-step reading of Log4Shell |

The topics are written from the official pages of each source and can become outdated (for example, NVD changed how it analyzes CVEs
in 2026). Each topic links to its official page so you can check the current state.
