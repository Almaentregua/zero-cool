import type { SourceResult, SourceStatus } from "../api";
import { STATUS_LABEL } from "../reportFormat";
import { NOT_AVAILABLE, formatDateTime, safeUrl } from "../format";
import SourceData from "./SourceData";

/** List of every source consulted for a CVE with its status, linking to each block. */
export function Summary({
  cveId,
  sources,
}: {
  cveId: string;
  sources: { source: string; source_name: string; status: SourceStatus }[];
}) {
  return (
    <nav aria-label={`Sources consulted for ${cveId}`} className="source-summary">
      <h3>Sources consulted ({sources.length})</h3>
      <ul>
        {sources.map((s) => (
          <li key={s.source}>
            <a href={`#${cveId}-${s.source}`}>{s.source_name}</a>{" "}
            <span className={`status status-${s.status}`}>{STATUS_LABEL[s.status]}</span>
          </li>
        ))}
      </ul>
    </nav>
  );
}

/** One source's answer: name, status, where it comes from, when, and its data. */
export function SourceBlock({ result: r }: { result: SourceResult }) {
  const origin = r.origin_url ? safeUrl(r.origin_url) : null;
  return (
    <article className="source-block" id={`${r.cve_id}-${r.source}`}>
      <header>
        <h3>{r.source_name}</h3>
        <span className={`status status-${r.status}`}>{STATUS_LABEL[r.status]}</span>
      </header>
      <p className="meta muted">
        Source:{" "}
        {origin ? (
          <a href={origin} target="_blank" rel="noopener noreferrer">
            {origin}
          </a>
        ) : (
          NOT_AVAILABLE
        )}
        {" · "}Retrieved: {formatDateTime(r.retrieved_at)}
      </p>
      {r.status !== "ok" && r.message && <p className={r.status === "error" ? "error" : ""}>{r.message}</p>}
      {r.status === "ok" && r.data && <SourceData source={r.source} data={r.data} />}
    </article>
  );
}
