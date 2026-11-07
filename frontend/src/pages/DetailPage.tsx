import { Link, useLocation, useParams } from "react-router-dom";

import { ApiError, fetchVulnerability } from "../api";
import { SeverityBadge, YesNo } from "../components/Badges";
import { DocHelp } from "../components/DocHelp";
import { NOT_AVAILABLE, formatDate, formatEpss, formatScore, formatText, safeUrl } from "../format";
import { useFetch } from "../useFetch";

export default function DetailPage() {
  const { cveId = "" } = useParams();
  const location = useLocation();
  const from = (location.state as { from?: string } | null)?.from ?? "";
  const state = useFetch((signal) => fetchVulnerability(cveId, signal), cveId);

  return (
    <>
      <p>
        <Link to={from ? `/?${from}` : "/"}>← Back to list</Link>
      </p>
      {state.status === "loading" && <p role="status">Loading…</p>}
      {state.status === "error" && (
        <p role="alert" className="error">
          {state.error instanceof ApiError && state.error.status === 404
            ? `${cveId.toUpperCase()} is not in the database.`
            : `Could not load this vulnerability: ${state.error.message}`}
        </p>
      )}
      {state.status === "ok" && <Detail v={state.data} />}
    </>
  );
}

function Detail({ v }: { v: Awaited<ReturnType<typeof fetchVulnerability>> }) {
  const links = v.references.map((url) => ({ url, href: safeUrl(url) }));
  return (
    <article>
      <h1>{v.cve_id}</h1>
      <p className="subtitle">{formatText(v.title)}</p>

      <dl className="fields">
        <dt>
          Severity
          <DocHelp slug="cvss" label="severity" />
        </dt>
        <dd>
          <SeverityBadge severity={v.severity} />
        </dd>
        <dt>
          CVSS score
          <DocHelp slug="cvss" label="CVSS" />
        </dt>
        <dd>{formatScore(v.cvss_score)}</dd>
        <dt>
          CVSS vector
          <DocHelp slug="cvss-vector" label="the CVSS vector" />
        </dt>
        <dd>{formatText(v.cvss_vector)}</dd>
        <dt>
          EPSS probability
          <DocHelp slug="epss" label="EPSS" />
        </dt>
        <dd>{formatEpss(v.epss_score)}</dd>
        <dt>
          EPSS percentile
          <DocHelp slug="epss" label="the EPSS percentile" />
        </dt>
        <dd>{formatEpss(v.epss_percentile)}</dd>
        <dt>
          Actively exploited (KEV)
          <DocHelp slug="kev" label="KEV" />
        </dt>
        <dd>
          <YesNo value={v.is_kev} />
        </dd>
        <dt>
          Used in ransomware
          <DocHelp slug="kev" label="ransomware use" />
        </dt>
        <dd>
          <YesNo value={v.ransomware_use} yesClass="danger" />
        </dd>
        <dt>Vendor</dt>
        <dd>{formatText(v.vendor)}</dd>
        <dt>Product</dt>
        <dd>{formatText(v.product)}</dd>
        <dt>Technologies</dt>
        <dd>{v.technologies.length > 0 ? v.technologies.join(", ") : NOT_AVAILABLE}</dd>
        <dt>Date added to KEV</dt>
        <dd>{formatDate(v.date_added)}</dd>
        <dt>
          KEV remediation due
          <DocHelp slug="kev" label="the KEV due date" />
        </dt>
        <dd>{formatDate(v.kev_due_date)}</dd>
        <dt>Published</dt>
        <dd>{formatDate(v.published_at)}</dd>
        <dt>Last modified</dt>
        <dd>{formatDate(v.modified_at)}</dd>
      </dl>

      <h2>Description</h2>
      {/* Plain text on purpose: the text comes from external sources. */}
      <p className="description">{formatText(v.description)}</p>

      <h2>Affected packages</h2>
      {v.advisories.length === 0 ? (
        <p>No Maven or npm package advisory mentions this CVE.</p>
      ) : (
        <ul>
          {v.advisories.map((a) => (
            <li key={a.id}>
              <Link to={`/advisory/${a.id}`}>{a.id}</Link> <SeverityBadge severity={a.severity} />{" "}
              {formatText(a.summary)}
              <div className="muted">{a.packages.map((p) => `${p.ecosystem}: ${p.name}`).join(", ")}</div>
            </li>
          ))}
        </ul>
      )}

      <h2>References</h2>
      {links.length === 0 ? (
        <p>{NOT_AVAILABLE}</p>
      ) : (
        <ul>
          {links.map(({ url, href }) => (
            <li key={url}>
              {href ? (
                <a href={href} target="_blank" rel="noopener noreferrer">
                  {url}
                </a>
              ) : (
                url
              )}
            </li>
          ))}
        </ul>
      )}
    </article>
  );
}
