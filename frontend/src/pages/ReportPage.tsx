import { useState, type FormEvent } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";

import {
  ApiError,
  deleteReport,
  fetchReport,
  refreshReport,
  updateReport,
  type Change,
  type ReportDetail,
  type ReportUpdate,
} from "../api";
import { ModeSwitch, NotesView } from "../components/Notes";
import { SourceBlock, Summary } from "../components/SourceBlock";
import { formatDateTime, parseCveIds } from "../format";
import { useNotesMode } from "../notesMode";
import { describeChange } from "../reportFormat";
import { useFetch } from "../useFetch";

/** A saved report: notes, status, CVEs, and the snapshot of every source. */
export default function ReportPage() {
  const { reportId = "" } = useParams();
  const state = useFetch((signal) => fetchReport(reportId, signal), reportId);
  return (
    <>
      <p>
        <Link to="/reports">← Back to reports</Link>
      </p>
      {state.status === "loading" && <p role="status">Loading…</p>}
      {state.status === "error" && (
        <p role="alert" className="error">
          {state.error instanceof ApiError && state.error.status === 404
            ? "This report does not exist."
            : `Could not load this report: ${state.error.message}`}
        </p>
      )}
      {state.status === "ok" && <ReportView key={state.data.id} initial={state.data} />}
    </>
  );
}

function ReportView({ initial }: { initial: ReportDetail }) {
  const navigate = useNavigate();
  const [report, setReport] = useState(initial);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [changes, setChanges] = useState<Change[] | null>(null);
  const [mode, setMode] = useNotesMode();
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(report.notes);
  const [title, setTitle] = useState(report.title);
  const [newCves, setNewCves] = useState("");

  async function run<T>(label: string, action: () => Promise<T>): Promise<T | undefined> {
    setBusy(label);
    setError(null);
    try {
      return await action();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unknown error");
      return undefined;
    } finally {
      setBusy(null);
    }
  }

  async function patch(label: string, changesToApply: ReportUpdate): Promise<boolean> {
    const updated = await run(label, () => updateReport(report.id, changesToApply));
    if (!updated) return false;
    setReport(updated);
    setTitle(updated.title);
    return true;
  }

  async function saveNotes() {
    if (await patch("Saving notes…", { notes: draft })) setEditing(false);
  }

  async function addCves(event: FormEvent) {
    event.preventDefault();
    const { valid, invalid } = parseCveIds(newCves);
    if (invalid.length > 0) {
      setError(`Not a valid CVE id (expected CVE-YYYY-NNNN): ${invalid.join(", ")}`);
      return;
    }
    if (valid.length > 0 && (await patch("Investigating the new CVEs…", { add_cves: valid }))) {
      setNewCves("");
    }
  }

  async function refresh() {
    const response = await run("Refreshing from the sources…", () => refreshReport(report.id));
    if (response) {
      setReport(response.report);
      setChanges(response.changes);
    }
  }

  return (
    <article>
      <h1 className="page-title">{report.title}</h1>
      <p className="subtitle">
        {report.status === "done" ? "Done" : "Open"} · created {formatDateTime(report.created_at)} ·
        updated {formatDateTime(report.updated_at)}
      </p>
      {busy && <p role="status">{busy}</p>}
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}

      <section aria-label="Report settings" className="report-bar">
        <label>
          Title
          <input value={title} onChange={(e) => setTitle(e.target.value)} maxLength={200} />
        </label>
        <button
          type="button"
          className="secondary"
          disabled={busy !== null || title.trim() === "" || title.trim() === report.title}
          onClick={() => patch("Saving…", { title: title.trim() })}
        >
          Rename
        </button>
        <button
          type="button"
          className="secondary"
          disabled={busy !== null}
          onClick={() => patch("Saving…", { status: report.status === "done" ? "open" : "done" })}
        >
          {report.status === "done" ? "Reopen" : "Mark as done"}
        </button>
        <button type="button" disabled={busy !== null} onClick={refresh}>
          Refresh from the sources
        </button>
        <button
          type="button"
          className="secondary danger"
          disabled={busy !== null}
          onClick={async () => {
            if (!window.confirm(`Delete the report "${report.title}"? This cannot be undone.`)) return;
            const deleted = await run("Deleting…", async () => {
              await deleteReport(report.id);
              return true;
            });
            if (deleted) navigate("/reports");
          }}
        >
          Delete
        </button>
      </section>

      {changes !== null && (
        <section aria-label="Changes since the last snapshot" className="changes">
          <h2>Changes in this refresh</h2>
          {changes.length === 0 ? (
            <p>Nothing changed: every source answered the same as before.</p>
          ) : (
            <ul>
              {changes.map((c) => (
                <li key={`${c.cve_id}-${c.source}`}>{describeChange(c)}</li>
              ))}
            </ul>
          )}
        </section>
      )}

      <h2>Notes</h2>
      <ModeSwitch mode={mode} onChange={setMode} />
      {editing ? (
        <div className="notes-editor">
          <label>
            Notes (Markdown)
            <textarea value={draft} onChange={(e) => setDraft(e.target.value)} rows={10} maxLength={100000} />
          </label>
          <h3>Preview</h3>
          <NotesView text={draft} mode={mode} />
          <div className="actions">
            <button type="button" disabled={busy !== null} onClick={saveNotes}>
              Save notes
            </button>
            <button
              type="button"
              className="secondary"
              onClick={() => {
                setDraft(report.notes);
                setEditing(false);
              }}
            >
              Cancel
            </button>
          </div>
        </div>
      ) : (
        <>
          <NotesView text={report.notes} mode={mode} />
          <button
            type="button"
            className="secondary"
            onClick={() => {
              setDraft(report.notes);
              setEditing(true);
            }}
          >
            Edit notes
          </button>
        </>
      )}

      <h2>CVEs in this report</h2>
      <ul className="cve-chips">
        {report.cves.map((cve) => (
          <li key={cve}>
            <a href={`#cve-${cve}`}>{cve}</a>{" "}
            <button
              type="button"
              className="secondary"
              aria-label={`Remove ${cve}`}
              disabled={busy !== null || report.cves.length <= 1}
              onClick={() => patch("Removing…", { remove_cves: [cve] })}
            >
              Remove
            </button>
          </li>
        ))}
      </ul>
      <form className="add-cves" onSubmit={addCves}>
        <label>
          Add CVEs
          <input
            value={newCves}
            onChange={(e) => setNewCves(e.target.value)}
            placeholder="CVE-2022-22965"
            autoComplete="off"
            spellCheck={false}
          />
        </label>
        <button type="submit" disabled={busy !== null || newCves.trim() === ""}>
          Add and investigate
        </button>
      </form>

      <p className="muted">
        Saved snapshot: each block shows what the source said when it was retrieved, not necessarily what it
        says today. Use “Refresh from the sources” to update it.
      </p>
      {report.cves.map((cve) => {
        const results = report.results.filter((r) => r.cve_id === cve);
        return (
          <section className="cve-section" key={cve} id={`cve-${cve}`} aria-label={cve}>
            <h2>{cve}</h2>
            <Summary cveId={cve} sources={results} />
            {results.map((r) => (
              <SourceBlock key={r.source} result={r} />
            ))}
          </section>
        );
      })}
    </article>
  );
}
