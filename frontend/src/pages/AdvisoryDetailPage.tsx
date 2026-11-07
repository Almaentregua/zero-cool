import { Link, useLocation, useParams } from "react-router-dom";

import { ApiError, fetchAdvisory, type AdvisoryDetail } from "../api";
import { SeverityBadge, YesNo } from "../components/Badges";
import { DocHelp } from "../components/DocHelp";
import { NOT_AVAILABLE, describeRange, formatDate, formatEpss, formatText, safeUrl } from "../format";
import { useFetch } from "../useFetch";

export default function AdvisoryDetailPage() {
  const { advisoryId = "" } = useParams();
  const location = useLocation();
  const from = (location.state as { from?: string } | null)?.from ?? "";
  const state = useFetch((signal) => fetchAdvisory(advisoryId, signal), advisoryId);

  return (
    <>
      <p>
        <Link to={from ? `/advisories?${from}` : "/advisories"}>← Back to advisories</Link>
      </p>
      {state.status === "loading" && <p role="status">Loading…</p>}
      {state.status === "error" && (
        <p role="alert" className="error">
          {state.error instanceof ApiError && state.error.status === 404
            ? `${advisoryId} is not in the database.`
            : `Could not load this advisory: ${state.error.message}`}
        </p>
      )}
      {state.status === "ok" && <Detail a={state.data} />}
    </>
  );
}

function Detail({ a }: { a: AdvisoryDetail }) {
  const links = a.references.map((url) => ({ url, href: safeUrl(url) }));
  return (
    <article>
      <h1>{a.id}</h1>
      <p className="subtitle">{formatText(a.summary)}</p>

      <dl className="fields">
        <dt>
          Severity
          <DocHelp slug="cvss" label="severity" />
        </dt>
        <dd>
          <SeverityBadge severity={a.severity} />
        </dd>
        <dt>
          CVSS vector
          <DocHelp slug="cvss-vector" label="the CVSS vector" />
        </dt>
        <dd>{formatText(a.cvss_vector)}</dd>
        <dt>
          EPSS probability
          <DocHelp slug="epss" label="EPSS" />
        </dt>
        <dd>{formatEpss(a.epss_score)}</dd>
        <dt>
          EPSS percentile
          <DocHelp slug="epss" label="the EPSS percentile" />
        </dt>
        <dd>{formatEpss(a.epss_percentile)}</dd>
        <dt>
          Reviewed by GitHub
          <DocHelp group="sources" slug="github-advisories" label="GitHub Advisories" />
        </dt>
        <dd>
          <YesNo value={a.github_reviewed} />
        </dd>
        <dt>Technologies</dt>
        <dd>{a.technologies.length > 0 ? a.technologies.join(", ") : NOT_AVAILABLE}</dd>
        <dt>
          CVE
          <DocHelp slug="cve" label="CVE" />
        </dt>
        <dd>
          {a.cves.length === 0
            ? NOT_AVAILABLE
            : a.cves.map((c, index) => (
                <span key={c.cve_id}>
                  {index > 0 && ", "}
                  {c.in_database ? <Link to={`/cve/${c.cve_id}`}>{c.cve_id}</Link> : c.cve_id}
                </span>
              ))}
        </dd>
        <dt>Published</dt>
        <dd>{formatDate(a.published_at)}</dd>
        <dt>Last modified</dt>
        <dd>{formatDate(a.modified_at)}</dd>
      </dl>

      <h2>Affected packages</h2>
      {a.packages.length === 0 ? (
        <p>{NOT_AVAILABLE}</p>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>
                  Ecosystem
                  <DocHelp slug="package-advisories" label="ecosystems" />
                </th>
                <th>Package</th>
                <th>
                  Affected versions (as reported)
                  <DocHelp slug="version-ranges" label="affected versions" />
                </th>
                <th>
                  Fixed in
                  <DocHelp slug="version-ranges" label="fixed versions" />
                </th>
              </tr>
            </thead>
            <tbody>
              {a.packages.map((p) => (
                <tr key={`${p.ecosystem}:${p.name}`}>
                  <td>{p.ecosystem}</td>
                  <td className="wrap">{p.name}</td>
                  <td>
                    {p.ranges.length === 0
                      ? NOT_AVAILABLE
                      : p.ranges.map((r, index) => <div key={index}>{describeRange(r)}</div>)}
                  </td>
                  <td>{p.fixed_versions.length > 0 ? p.fixed_versions.join(", ") : NOT_AVAILABLE}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <h2>Details</h2>
      {/* Plain text on purpose: the text comes from an external source. */}
      <p className="description">{formatText(a.details)}</p>

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
