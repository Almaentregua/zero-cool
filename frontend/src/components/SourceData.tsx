/**
 * Renders the `data` of each research source.
 *
 * Everything here comes from external sources, so values are only ever rendered as React
 * text (never as HTML) and links go through `safeUrl`. Fields the source did not provide
 * are shown as "Not available". Each source keeps its own block: values from different
 * sources are never merged.
 */
import { Link } from "react-router-dom";
import type { ReactNode } from "react";

import { NOT_AVAILABLE, formatDate, formatEpss, safeUrl } from "../format";

type Data = Record<string, unknown>;

const str = (v: unknown): string | null => (typeof v === "string" && v !== "" ? v : null);
const num = (v: unknown): number | null => (typeof v === "number" ? v : null);
const bool = (v: unknown): boolean | null => (typeof v === "boolean" ? v : null);
const list = (v: unknown): Data[] =>
  Array.isArray(v) ? v.filter((x): x is Data => typeof x === "object" && x !== null) : [];
const strings = (v: unknown): string[] =>
  Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
const obj = (v: unknown): Data | null =>
  typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Data) : null;

function text(value: string | null): ReactNode {
  return value ?? <span className="muted">{NOT_AVAILABLE}</span>;
}

function yesNo(value: boolean | null): ReactNode {
  if (value === null) return text(null);
  return value ? "Yes" : "No";
}

function Fields({ rows }: { rows: [string, ReactNode][] }) {
  return (
    <dl className="fields">
      {rows.map(([label, value]) => (
        <div className="field-row" key={label}>
          <dt>{label}</dt>
          <dd>{value}</dd>
        </div>
      ))}
    </dl>
  );
}

function ExternalLink({ url, label }: { url: string; label?: string }) {
  const href = safeUrl(url);
  return href ? (
    <a href={href} target="_blank" rel="noopener noreferrer">
      {label ?? url}
    </a>
  ) : (
    <span>{label ?? url}</span>
  );
}

function Links({ urls }: { urls: string[] }) {
  if (urls.length === 0) return <p className="muted">{NOT_AVAILABLE}</p>;
  return (
    <ul>
      {urls.map((url) => (
        <li key={url}>
          <ExternalLink url={url} />
        </li>
      ))}
    </ul>
  );
}

function Cvss({ items }: { items: Data[] }) {
  if (items.length === 0) return <>{text(null)}</>;
  return (
    <>
      {items.map((c, i) => (
        <div key={i}>
          CVSS {str(c.version) ?? "?"}: {num(c.score)?.toFixed(1) ?? NOT_AVAILABLE}
          {str(c.severity) ? ` (${str(c.severity)})` : ""}
          {str(c.vector) ? <div className="muted">{str(c.vector)}</div> : null}
        </div>
      ))}
    </>
  );
}

function Cwes({ items }: { items: Data[] }) {
  if (items.length === 0) return <>{text(null)}</>;
  return (
    <>
      {items.map((c, i) => (
        <div key={i}>{[str(c.id), str(c.description)].filter(Boolean).join(" ")}</div>
      ))}
    </>
  );
}

function Kev({ d }: { d: Data }) {
  const inKev = bool(d.in_kev);
  return (
    <Fields
      rows={[
        ["In CISA KEV", inKev === null ? text(null) : inKev ? "Yes: actively exploited" : "No: not listed"],
        ...(inKev
          ? ([
              ["Name", text(str(d.title))],
              ["Vendor / product", text([str(d.vendor), str(d.product)].filter(Boolean).join(" / ") || null)],
              ["Added to KEV", formatDate(str(d.date_added))],
              ["Remediation due", formatDate(str(d.due_date))],
              ["Used in ransomware", yesNo(bool(d.ransomware_use))],
            ] as [string, ReactNode][])
          : []),
      ]}
    />
  );
}

function Nvd({ d }: { d: Data }) {
  const score = num(d.cvss_score);
  return (
    <>
      <Fields
        rows={[
          ["CVSS score", score === null ? text(null) : `${score.toFixed(1)}${str(d.severity) ? ` (${str(d.severity)})` : ""}`],
          ["CVSS vector", text(str(d.cvss_vector))],
          ["Published", formatDate(str(d.published_at))],
          ["Last modified", formatDate(str(d.modified_at))],
          ["Description", <span className="description" key="d">{text(str(d.description))}</span>],
        ]}
      />
      <h4>References</h4>
      <Links urls={strings(d.references)} />
    </>
  );
}

function Epss({ d }: { d: Data }) {
  return (
    <Fields
      rows={[
        ["Exploitation probability (30 days)", formatEpss(num(d.score))],
        ["Percentile", formatEpss(num(d.percentile))],
      ]}
    />
  );
}

function Osv({ d }: { d: Data }) {
  const advisories = list(d.advisories);
  return (
    <>
      {advisories.map((a, i) => {
        const id = str(a.id) ?? "";
        return (
          <div className="sub-block" key={id || i}>
            <h4>
              {id ? <Link to={`/advisory/${encodeURIComponent(id)}`}>{id}</Link> : NOT_AVAILABLE}
              {str(a.severity) ? ` · ${str(a.severity)}` : ""}
            </h4>
            <p>{text(str(a.summary))}</p>
            <ul>
              {list(a.packages).map((p, j) => (
                <li key={j}>
                  {str(p.ecosystem)}: {str(p.name)} · fixed in: {str(p.fixed_versions) ?? NOT_AVAILABLE}
                </li>
              ))}
            </ul>
          </div>
        );
      })}
    </>
  );
}

function Affected({ items }: { items: Data[] }) {
  if (items.length === 0) return <p className="muted">{NOT_AVAILABLE}</p>;
  return (
    <ul>
      {items.map((a, i) => (
        <li key={i}>
          {[str(a.vendor), str(a.product)].filter(Boolean).join(" / ") || NOT_AVAILABLE}
          {list(a.versions).map((v, j) => (
            <div className="muted" key={j}>
              {[
                str(v.status),
                str(v.version),
                str(v.less_than) ? `before ${str(v.less_than)}` : null,
                str(v.less_than_or_equal) ? `up to ${str(v.less_than_or_equal)}` : null,
              ]
                .filter(Boolean)
                .join(" ")}
            </div>
          ))}
        </li>
      ))}
    </ul>
  );
}

function CveOrg({ d }: { d: Data }) {
  return (
    <>
      <Fields
        rows={[
          ["Record state", text(str(d.state))],
          ["Assigned by (CNA)", text(str(d.assigner))],
          ["Published", formatDate(str(d.published_at))],
          ["Last updated", formatDate(str(d.updated_at))],
          ["Title", text(str(d.title))],
          ["CVSS (from the CNA)", <Cvss items={list(d.cvss)} key="c" />],
          ["Weaknesses (CWE)", <Cwes items={list(d.cwes)} key="w" />],
          ["Description", <span className="description" key="d">{text(str(d.description))}</span>],
        ]}
      />
      <h4>Affected products (as declared by the CNA)</h4>
      <Affected items={list(d.affected)} />
      <h4>References (from the CNA)</h4>
      <Links urls={strings(d.references)} />
    </>
  );
}

function Vulnrichment({ d }: { d: Data }) {
  const ssvc = obj(d.ssvc);
  return (
    <Fields
      rows={[
        ["SSVC: exploitation", text(str(ssvc?.exploitation))],
        ["SSVC: automatable", text(str(ssvc?.automatable))],
        ["SSVC: technical impact", text(str(ssvc?.technical_impact))],
        ["SSVC version / date", text([str(ssvc?.version), str(ssvc?.timestamp)].filter(Boolean).join(" · ") || null)],
        ["CVSS (from CISA)", <Cvss items={list(d.cvss)} key="c" />],
        ["Weaknesses (CWE, from CISA)", <Cwes items={list(d.cwes)} key="w" />],
      ]}
    />
  );
}

const AUTHORS: Record<string, string> = { cna: "the CNA", cisa: "CISA" };

function Cwe({ d }: { d: Data }) {
  return (
    <>
      {list(d.cwes).map((c, i) => {
        const url = str(c.url);
        const id = str(c.id) ?? NOT_AVAILABLE;
        const name = str(c.name);
        return (
          <div className="sub-block" key={id + i}>
            <h4>
              {url ? <ExternalLink url={url} label={id} /> : id}
              {name ? `: ${name}` : ""}
            </h4>
            <p className="muted">Listed in the CVE record by: {strings(c.listed_by).map((w) => AUTHORS[w] ?? w).join(", ") || NOT_AVAILABLE}</p>
            {name === null ? (
              <p className="muted">MITRE has no weakness or category with this id.</p>
            ) : (
              <Fields
                rows={[
                  ["Kind", text([str(c.kind), str(c.abstraction)].filter(Boolean).join(" · ") || null)],
                  ["Status", text(str(c.status))],
                  ["Likelihood of exploit", text(str(c.likelihood_of_exploit))],
                  ["Description", <span className="description" key="d">{text(str(c.description))}</span>],
                ]}
              />
            )}
            {list(c.consequences).length > 0 && (
              <>
                <h5>Common consequences</h5>
                <ul>
                  {list(c.consequences).map((q, j) => (
                    <li key={j}>
                      {strings(q.scope).join(", ")}: {strings(q.impact).join(", ")}
                      {str(q.note) ? <div className="muted">{str(q.note)}</div> : null}
                    </li>
                  ))}
                </ul>
              </>
            )}
          </div>
        );
      })}
    </>
  );
}

/** Fallback for a source without a dedicated view: its fields as plain text. */
function Generic({ d }: { d: Data }) {
  return (
    <Fields
      rows={Object.entries(d).map(([k, v]): [string, ReactNode] => [
        k,
        <span className="description" key={k}>{typeof v === "string" ? v : JSON.stringify(v)}</span>,
      ])}
    />
  );
}

const VIEWS: Record<string, (props: { d: Data }) => ReactNode> = {
  kev: Kev,
  nvd: Nvd,
  epss: Epss,
  osv: Osv,
  cve_org: CveOrg,
  vulnrichment: Vulnrichment,
  cwe: Cwe,
};

/** The data of one source, using its dedicated view when there is one. */
export default function SourceData({ source, data }: { source: string; data: Data }) {
  const View = VIEWS[source] ?? Generic;
  return <View d={data} />;
}
