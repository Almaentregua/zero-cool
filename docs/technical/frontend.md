# Frontend

React + Vite + TypeScript in `frontend/`. Routing with `react-router-dom`; no UI
or styling libraries (plain CSS in `src/index.css`, light and dark mode).

## Structure
| File | Purpose |
|------|---------|
| `src/api.ts` | API types and calls; `cleanListParams` keeps only known, non-empty params |
| `src/format.ts` | Display helpers: missing data -> "Not available"; `safeUrl` |
| `src/useFetch.ts` | Small hook: loads data, cancels the previous request |
| `src/pages/ListPage.tsx` | `/` - filters, table, sorting, pagination |
| `src/pages/DetailPage.tsx` | `/cve/:cveId` - all fields, description, references, related package advisories |
| `src/pages/AdvisoryListPage.tsx` | `/advisories` - package advisories with filters, sorting, pagination |
| `src/pages/AdvisoryDetailPage.tsx` | `/advisory/:advisoryId` - packages with version ranges, CVEs, details, references |
| `src/pages/InvestigationPage.tsx` | `/investigations?cves=A,B` - one section per CVE, a summary of sources consulted and one block per source |
| `src/components/SourceData.tsx` | One view per research source (`kev`, `nvd`, `epss`, `osv`, `cve_org`, `vulnrichment`, `cwe`) plus a generic fallback |
| `src/pages/ReportListPage.tsx` | `/reports` - saved reports, most recently updated first |
| `src/pages/ReportPage.tsx` | `/reports/:reportId` - notes, status, CVEs, refresh with changes, delete, and the saved snapshot |
| `src/components/Notes.tsx`, `src/notesMode.ts` | Notes view (Markdown or plain text) and the remembered display mode |
| `src/components/` | `FilterBar`, `AdvisoryFilterBar`, `Pagination`, severity and yes/no badges |

## Design decisions
- **State lives in the URL** (`useSearchParams`): filters, sort and page can be shared,
  bookmarked and survive reload. The filter form applies on submit, not per keystroke.
- **The list page links to the detail with `state.from`**, so "Back to list" restores the filters.
- **Untrusted data.** All external text is rendered through React (escaped); there is no
  `dangerouslySetInnerHTML`. Reference links are only clickable if `safeUrl` accepts them
  (http/https), and open with `rel="noopener noreferrer"`. Tests cover HTML in titles and
  descriptions and `javascript:` links.
- **Missing data** is `null` from the API and always displayed as "Not available".
- **Dev proxy.** `/api` is proxied to `VITE_API_URL` (see `vite.config.ts`), so the browser
  uses one origin and no CORS configuration is needed in development.

- **Two resources, linked.** KEV vulnerabilities and package advisories are separate lists
  (see ADR 0003). The CVE page lists related advisories; an advisory links to a CVE page only
  when the API says `in_database` (otherwise the page would not exist).
- **Version ranges are repeated, not interpreted.** `describeRange` turns OSV events into text
  ("introduced 2.13.0 → fixed 2.15.0"). Whether a given version is affected is not computed,
  because Maven and npm order versions differently.

## Investigations page
- The CVE ids live in the URL (`?cves=`); each CVE is its own component with its own request,
  so they load independently. Invalid ids are reported and never sent to the API (max 10).
- **Sources are always explicit:** a summary lists every source consulted with its status
  (Has data / No data / Error, always as text, not only color); each block shows the source
  name, its origin link, the retrieval time and, if not `ok`, the reason. Sources are never merged.
- `SourceData` knows the `data` shape of each source; a new source works without a view (the
  generic fallback prints its fields as text) and gets a dedicated view when worth it.
- "Refresh from the sources" calls the API with `refresh=true`.
- "Save as report" creates a report from the investigated CVEs (title optional, defaults to the CVE ids)
  and opens it. The backend queries the sources again (usually served from its cache).

## Reports page and notes
- Blocks are the same `SourceBlock` as in the investigation, but they show the **saved snapshot**,
  with a reminder that it may differ from what the sources say today.
- **Refresh** shows what changed (`describeChange`); a source that failed during the refresh keeps its
  old block and says so. Delete asks for confirmation.
- **Notes are Markdown, shown in the mode the user picks** (Markdown or Plain text). The mode is only
  a display preference kept in `localStorage` (wrapped in try/catch); notes are always stored exactly as
  typed, so switching never loses anything. While editing there is a preview in the chosen mode.
- **Dependency added: `react-markdown`** (10.x). Reason: rendering Markdown safely by hand would mean
  writing a parser. It builds React elements (no `dangerouslySetInnerHTML`), and we configure it with
  `skipHtml` (raw HTML in notes is dropped), `urlTransform` limited to http(s) via `safeUrl`, links with
  `rel="noopener noreferrer"`, and images replaced by their alt text so nothing is loaded from third
  parties. Tests cover `<script>`, a `javascript:` link and a remote image.

## Tests
`make test-frontend` (Vitest + Testing Library, `fetch` is mocked; no real API calls).
