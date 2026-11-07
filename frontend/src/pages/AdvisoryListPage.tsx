import type { ReactNode } from "react";
import { Link, useSearchParams } from "react-router-dom";

import { cleanAdvisoryParams, fetchAdvisories, fetchTechnologies } from "../api";
import AdvisoryFilterBar from "../components/AdvisoryFilterBar";
import { SeverityBadge } from "../components/Badges";
import { DocHelp } from "../components/DocHelp";
import Pagination from "../components/Pagination";
import { NOT_AVAILABLE, formatDate, formatEpss, formatText } from "../format";
import { useFetch } from "../useFetch";

type SortKey = "published" | "epss";
const VISIBLE_PACKAGES = 2;

export default function AdvisoryListPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const params = cleanAdvisoryParams(searchParams);
  const key = params.toString();

  const list = useFetch((signal) => fetchAdvisories(params, signal), key);
  const technologies = useFetch((signal) => fetchTechnologies(signal), "technologies");

  const sort = (params.get("sort") ?? "published") as SortKey;
  const order = params.get("order") ?? "desc";
  const page = Number(params.get("page") ?? "1") || 1;

  function sortBy(column: SortKey) {
    const next = new URLSearchParams(params);
    next.set("sort", column);
    next.set("order", sort === column && order === "desc" ? "asc" : "desc");
    next.delete("page");
    setSearchParams(next);
  }

  function goTo(target: number) {
    const next = new URLSearchParams(params);
    next.set("page", String(target));
    setSearchParams(next);
  }

  function sortableHeader(column: SortKey, label: string, help?: ReactNode) {
    const current = sort === column ? (order === "desc" ? "descending" : "ascending") : "none";
    return (
      <th aria-sort={current}>
        <button type="button" className="link-button" onClick={() => sortBy(column)}>
          {label}
          {sort === column && <span aria-hidden="true"> {order === "desc" ? "▼" : "▲"}</span>}
        </button>
        {help}
      </th>
    );
  }

  return (
    <>
      <h1 className="page-title">Package advisories</h1>
      <p className="muted">
        Security advisories for Maven and npm packages (GitHub Advisory Database, via OSV).
      </p>
      <AdvisoryFilterBar
        params={params}
        technologies={technologies.status === "ok" ? technologies.data : []}
        onApply={(next) => setSearchParams(next)}
      />

      {list.status === "loading" && <p role="status">Loading…</p>}
      {list.status === "error" && (
        <p role="alert" className="error">
          Could not load advisories: {list.error.message}
        </p>
      )}
      {list.status === "ok" && (
        <>
          <p role="status">
            {list.data.total} {list.data.total === 1 ? "advisory" : "advisories"} found
          </p>
          {list.data.items.length === 0 ? (
            <p>No advisories match these filters.</p>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>
                      Advisory
                      <DocHelp slug="package-advisories" label="package advisories" />
                    </th>
                    <th>Summary</th>
                    <th>
                      Severity
                      <DocHelp slug="cvss" label="severity" />
                    </th>
                    {sortableHeader("epss", "EPSS", <DocHelp slug="epss" label="EPSS" />)}
                    <th>
                      CVE
                      <DocHelp slug="cve" label="CVE" />
                    </th>
                    <th>Packages</th>
                    {sortableHeader("published", "Published")}
                  </tr>
                </thead>
                <tbody>
                  {list.data.items.map((a) => (
                    <tr key={a.id}>
                      <td>
                        <Link to={`/advisory/${a.id}`} state={{ from: searchParams.toString() }}>
                          {a.id}
                        </Link>
                      </td>
                      <td>{formatText(a.summary)}</td>
                      <td>
                        <SeverityBadge severity={a.severity} />
                      </td>
                      <td>{formatEpss(a.epss_score)}</td>
                      <td>{a.cves.length > 0 ? a.cves.join(", ") : NOT_AVAILABLE}</td>
                      <td>
                        {a.packages.slice(0, VISIBLE_PACKAGES).map((p) => (
                          <div key={`${p.ecosystem}:${p.name}`} className="package-line">
                            <span className="badge tag">{p.ecosystem}</span> {p.name}
                          </div>
                        ))}
                        {a.packages.length > VISIBLE_PACKAGES && (
                          <div className="muted">+{a.packages.length - VISIBLE_PACKAGES} more</div>
                        )}
                      </td>
                      <td>{formatDate(a.published_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <Pagination page={page} pageSize={list.data.page_size} total={list.data.total} onChange={goTo} />
        </>
      )}
    </>
  );
}
