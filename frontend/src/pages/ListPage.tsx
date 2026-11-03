import { Link, useSearchParams } from "react-router-dom";

import { cleanListParams, fetchTechnologies, fetchVulnerabilities } from "../api";
import { SeverityBadge, YesNo } from "../components/Badges";
import FilterBar from "../components/FilterBar";
import Pagination from "../components/Pagination";
import { formatDate, formatEpss, formatScore, formatText } from "../format";
import { useFetch } from "../useFetch";

type SortKey = "date_added" | "cvss" | "epss";

export default function ListPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const params = cleanListParams(searchParams);
  const key = params.toString();

  const list = useFetch((signal) => fetchVulnerabilities(params, signal), key);
  const technologies = useFetch((signal) => fetchTechnologies(signal), "technologies");

  const sort = (params.get("sort") ?? "date_added") as SortKey;
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

  function arrow(column: SortKey) {
    if (sort !== column) return null;
    return <span aria-hidden="true"> {order === "desc" ? "▼" : "▲"}</span>;
  }

  function sortableHeader(column: SortKey, label: string) {
    const current = sort === column ? (order === "desc" ? "descending" : "ascending") : "none";
    return (
      <th aria-sort={current}>
        <button type="button" className="link-button" onClick={() => sortBy(column)}>
          {label}
          {arrow(column)}
        </button>
      </th>
    );
  }

  return (
    <>
      <FilterBar
        params={params}
        technologies={technologies.status === "ok" ? technologies.data : []}
        onApply={(next) => setSearchParams(next)}
      />

      {list.status === "loading" && <p role="status">Loading…</p>}
      {list.status === "error" && (
        <p role="alert" className="error">
          Could not load vulnerabilities: {list.error.message}
        </p>
      )}
      {list.status === "ok" && (
        <>
          <p role="status">
            {list.data.total} {list.data.total === 1 ? "vulnerability" : "vulnerabilities"} found
          </p>
          {list.data.items.length === 0 ? (
            <p>No vulnerabilities match these filters.</p>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>CVE</th>
                    <th>Title</th>
                    <th>Severity</th>
                    {sortableHeader("cvss", "CVSS")}
                    {sortableHeader("epss", "EPSS")}
                    <th>Exploited (KEV)</th>
                    <th>Ransomware</th>
                    {sortableHeader("date_added", "Date added")}
                  </tr>
                </thead>
                <tbody>
                  {list.data.items.map((v) => (
                    <tr key={v.cve_id}>
                      <td>
                        <Link to={`/cve/${v.cve_id}`} state={{ from: searchParams.toString() }}>
                          {v.cve_id}
                        </Link>
                      </td>
                      <td>
                        {formatText(v.title)}
                        {v.technologies.length > 0 && (
                          <div className="tags">
                            {v.technologies.map((t) => (
                              <span key={t} className="badge tag">
                                {t}
                              </span>
                            ))}
                          </div>
                        )}
                      </td>
                      <td>
                        <SeverityBadge severity={v.severity} />
                      </td>
                      <td>{formatScore(v.cvss_score)}</td>
                      <td>{formatEpss(v.epss_score)}</td>
                      <td>
                        <YesNo value={v.is_kev} />
                      </td>
                      <td>
                        <YesNo value={v.ransomware_use} yesClass="danger" />
                      </td>
                      <td>{formatDate(v.date_added)}</td>
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
