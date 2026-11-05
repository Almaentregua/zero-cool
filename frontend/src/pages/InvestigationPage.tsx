import { useState, type FormEvent } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";

import { createReport, fetchResearch } from "../api";
import { SourceBlock, Summary } from "../components/SourceBlock";
import { formatDateTime, parseCveIds } from "../format";
import { useFetch } from "../useFetch";

const MAX_CVES = 10;
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
      {ids.length > 0 && <SavePanel cves={ids} />}
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
          <Summary cveId={state.data.cve_id} sources={state.data.sources} />
          {state.data.results.map((r) => (
            <SourceBlock key={r.source} result={r} />
          ))}
        </>
      )}
    </section>
  );
}

/** Saves the investigated CVEs as a report (a snapshot of what every source says now). */
function SavePanel({ cves }: { cves: string[] }) {
  const navigate = useNavigate();
  const [title, setTitle] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function save(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const report = await createReport(title.trim() || cves.join(", "), cves);
      navigate(`/reports/${report.id}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unknown error");
      setBusy(false);
    }
  }

  return (
    <form className="save-panel" onSubmit={save}>
      <label>
        Save as a report to keep it and continue later
        <input
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          placeholder={cves.join(", ")}
          maxLength={200}
          aria-label="Report title"
        />
      </label>
      <button type="submit" disabled={busy}>
        {busy ? "Saving… (querying the sources)" : "Save as report"}
      </button>
      {error && (
        <p role="alert" className="error">
          Could not save the report: {error}
        </p>
      )}
    </form>
  );
}
