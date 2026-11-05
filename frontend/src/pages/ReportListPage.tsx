import { Link } from "react-router-dom";

import { fetchReports } from "../api";
import { formatDateTime } from "../format";
import { useFetch } from "../useFetch";

/** Saved investigation reports, most recently updated first. */
export default function ReportListPage() {
  const state = useFetch((signal) => fetchReports(signal), "reports");
  return (
    <>
      <h1 className="page-title">Reports</h1>
      <p className="subtitle">
        Saved investigations. Open one to read your notes, refresh its data and keep working. Start a
        new one from <Link to="/investigations">Investigations</Link>.
      </p>
      {state.status === "loading" && <p role="status">Loading…</p>}
      {state.status === "error" && (
        <p role="alert" className="error">
          Could not load the reports: {state.error.message}
        </p>
      )}
      {state.status === "ok" &&
        (state.data.length === 0 ? (
          <p>No reports yet.</p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Title</th>
                  <th>CVEs</th>
                  <th>Status</th>
                  <th>Last updated</th>
                </tr>
              </thead>
              <tbody>
                {state.data.map((r) => (
                  <tr key={r.id}>
                    <td className="wrap">
                      <Link to={`/reports/${r.id}`}>{r.title}</Link>
                    </td>
                    <td className="wrap">{r.cves.join(", ")}</td>
                    <td>{r.status === "done" ? "Done" : "Open"}</td>
                    <td>{formatDateTime(r.updated_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ))}
    </>
  );
}
