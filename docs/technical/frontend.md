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
| `src/pages/DetailPage.tsx` | `/cve/:cveId` - all fields, description, references |
| `src/components/` | `FilterBar`, severity and yes/no badges |

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

## Tests
`make test-frontend` (Vitest + Testing Library, `fetch` is mocked; no real API calls).
