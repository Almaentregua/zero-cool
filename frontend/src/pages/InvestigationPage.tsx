import { useState, type FormEvent } from "react";
import { useSearchParams } from "react-router-dom";

import { fetchResearch, type ResearchResponse, type SourceResult, type SourceStatus } from "../api";
import SourceData from "../components/SourceData";
import { NOT_AVAILABLE, formatDateTime, parseCveIds, safeUrl } from "../format";
import { useFetch } from "../useFetch";

const MAX_CVES = 10;
const STATUS_LABEL: Record<SourceStatus, string> = {
  ok: "Has data",
  no_data: "No data",
  error: "Error",
};

/** Investigate one or more CVEs: one clearly separated block per source. */
export default function InvestigationPage() {
  const [params, setParams] = useSearchParams();
  const current = params.get("cves") ?? "";
  const [input, setInput] = useState(current.replaceAll(",", " "));
  const { valid, invalid } = parseCveIds(current);
  const ids = valid.slice(0, MAX_CVES);

  function submit(event: FormEvent) {
    event.preventDefault();
    const parsed = parseCveIds(input);
    setParams(parsed.valid.length > 0 ? { cves: parsed.valid.join(",") } : {});
    if (parsed.valid.length === 0) setInput(input);
  }

  const typed = parseCveIds(input);
  return (
    <>
      <h1 className="page-title">Investigations</h1>
      <p className="subtitle">
        Look up any CVE, in the KEV catalog or not, and see what each source says about it. Every
        source is shown on its own, with where its data comes from and when it was retrieved.
      </p>
      <form className="filters" onSubmit={submit}>
        <label className="wide">
          CVE ids (separate several with spaces or commas, up to {MAX_CVES})
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="CVE-2021-44228"
            autoComplete="off"
            spellCheck={false}
          />
        </label>
        <div className="actions">
          <button type="submit" disabled={typed.valid.length === 0}>
            Investigate
          </button>
        </div>
      </form>
      {(invalid.length > 0 || valid.length > MAX_CVES) && (
        <p role="alert" className="error">
          {invalid.length > 0 && `Not a valid CVE id (expected CVE-YYYY-NNNN): ${invalid.join(", ")}. `}
          {valid.length > MAX_CVES && `Only the first ${MAX_CVES} CVEs are investigated.`}
        </p>
      )}
      {ids.map((id) => (
        <CveResearch key={id} cveId={id} />
      ))}
    </>
  );
}

function CveResearch({ cveId }: { cveId: string }) {
  const [refreshes, setRefreshes] = useState(0);
  const state = useFetch(
    (signal) => fetchResearch(cveId, refreshes > 0, signal),
    `${cveId}:${refreshes}`,
  );

  return (
    <section className="cve-section" aria-label={cveId}>
      <h2>{cveId}</h2>
      {state.status === "loading" && (
        <p role="status">Querying every source… this can take several seconds.</p>
      )}
      {state.status === "error" && (
        <p role="alert" className="error">
          Could not investigate {cveId}: {state.error.message}
        </p>
      )}
      {state.status === "ok" && (
        <>
          <p className="muted">
            Assembled {formatDateTime(state.data.generated_at)}.{" "}
            <button type="button" className="secondary" onClick={() => setRefreshes((n) => n + 1)}>
              Refresh from the sources
            </button>
          </p>
          <Summary data={state.data} />
          {state.data.results.map((r) => (
            <SourceBlock key={r.source} result={r} />
          ))}
        </>
      )}
    </section>
  );
}

function Summary({ data }: { data: ResearchResponse }) {
  return (
    <nav aria-label={`Sources consulted for ${data.cve_id}`} className="source-summary">
      <h3>Sources consulted ({data.sources.length})</h3>
      <ul>
        {data.sources.map((s) => (
          <li key={s.source}>
            <a href={`#${data.cve_id}-${s.source}`}>{s.source_name}</a>{" "}
            <span className={`status status-${s.status}`}>{STATUS_LABEL[s.status]}</span>
          </li>
        ))}
      </ul>
    </nav>
  );
}

function SourceBlock({ result: r }: { result: SourceResult }) {
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
