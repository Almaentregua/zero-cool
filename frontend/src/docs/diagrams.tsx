import { type ComponentType, useState } from "react";

/** Severity bands shared by CVSS 3.x and 4.0. */
const BANDS = [
  { label: "None", range: "0.0", cls: "none", flex: 1 },
  { label: "Low", range: "0.1 – 3.9", cls: "low", flex: 3.9 },
  { label: "Medium", range: "4.0 – 6.9", cls: "medium", flex: 3 },
  { label: "High", range: "7.0 – 8.9", cls: "high", flex: 2.9 },
  { label: "Critical", range: "9.0 – 10.0", cls: "critical", flex: 2 },
];

/** The CVSS severity scale as a proportional bar. Text carries the meaning; color only reinforces it. */
export function SeverityScale() {
  return (
    <figure className="diagram">
      <div className="scale" role="img" aria-label="CVSS severity scale: None 0.0, Low 0.1 to 3.9, Medium 4.0 to 6.9, High 7.0 to 8.9, Critical 9.0 to 10.0">
        {BANDS.map((band) => (
          <div key={band.label} className={`scale-band scale-${band.cls}`} style={{ flexGrow: band.flex }}>
            <strong>{band.label}</strong>
            <span>{band.range}</span>
          </div>
        ))}
      </div>
      <figcaption>Scale of CVSS 3.x and 4.0. CVSS 2.0 has only Low, Medium and High.</figcaption>
    </figure>
  );
}

interface Metric {
  name: string;
  values: Record<string, string>;
}

/** Base metrics of CVSS 3.1 with the meaning of each value. */
const METRICS: Record<string, Metric> = {
  AV: {
    name: "Attack Vector",
    values: {
      N: "Network: can be attacked remotely, even from the Internet",
      A: "Adjacent: needs to be on the same network segment",
      L: "Local: needs access to the machine",
      P: "Physical: needs to touch the device",
    },
  },
  AC: {
    name: "Attack Complexity",
    values: { L: "Low: works every time, no special conditions", H: "High: depends on conditions the attacker does not control" },
  },
  PR: {
    name: "Privileges Required",
    values: { N: "None: no login needed", L: "Low: a basic user account", H: "High: administrator-level access" },
  },
  UI: {
    name: "User Interaction",
    values: { N: "None: no person needs to do anything", R: "Required: a person must act (open a file, click a link)" },
  },
  S: {
    name: "Scope",
    values: {
      U: "Unchanged: the impact stays inside the vulnerable component",
      C: "Changed: the impact reaches beyond the vulnerable component",
    },
  },
  C: { name: "Confidentiality impact", values: { H: "High: total loss of confidentiality", L: "Low: some data exposed", N: "None" } },
  I: { name: "Integrity impact", values: { H: "High: total loss of integrity", L: "Low: some data can be changed", N: "None" } },
  A: { name: "Availability impact", values: { H: "High: the service can be taken down", L: "Low: reduced performance", N: "None" } },
};

const EXAMPLE_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H";

/** Explains one `KEY:VALUE` part of a CVSS 3.1 vector, or null when the part is unknown. */
export function describeVectorPart(part: string): { name: string; meaning: string } | null {
  const [key, value] = part.split(":");
  const metric = METRICS[key];
  const meaning = metric?.values[value];
  return metric && meaning ? { name: metric.name, meaning } : null;
}

/** A CVSS vector (Log4Shell's) whose parts can be selected to see what each one means. */
export function CvssVectorBreakdown() {
  const parts = EXAMPLE_VECTOR.split("/");
  const [selected, setSelected] = useState<string | null>(null);
  const info = selected ? describeVectorPart(selected) : null;

  return (
    <figure className="diagram">
      <div className="vector" role="group" aria-label="Parts of the vector, select one to read its meaning">
        {parts.map((part, index) =>
          index === 0 ? (
            <span key={part} className="vector-version">
              {part}
            </span>
          ) : (
            <button
              key={part}
              type="button"
              className={`vector-part${selected === part ? " selected" : ""}`}
              aria-pressed={selected === part}
              onClick={() => setSelected(part)}
              onMouseEnter={() => setSelected(part)}
            >
              {part}
            </button>
          ),
        )}
      </div>
      <p className="vector-info" aria-live="polite">
        {info ? (
          <>
            <strong>{info.name}</strong>: {info.meaning}
          </>
        ) : (
          <span className="muted">Select or hover a part of the vector.</span>
        )}
      </p>
      <figcaption>The vector of Log4Shell (CVE-2021-44228), score 10.0. The first part is the CVSS version.</figcaption>
    </figure>
  );
}

function Box({ x, y, w, title, lines }: { x: number; y: number; w: number; title: string; lines: string[] }) {
  const h = 26 + lines.length * 17;
  return (
    <g>
      <rect x={x} y={y} width={w} height={h} rx={8} className="dg-box" />
      <text x={x + w / 2} y={y + 20} textAnchor="middle" className="dg-title">
        {title}
      </text>
      {lines.map((line, i) => (
        <text key={line} x={x + w / 2} y={y + 38 + i * 17} textAnchor="middle" className="dg-text">
          {line}
        </text>
      ))}
    </g>
  );
}

/** How a CVE relates to the weakness type, the affected products and the package advisories. */
export function CveCweCpe() {
  return (
    <figure className="diagram">
      <svg viewBox="0 0 640 250" role="img" aria-label="A CVE is one case of a CWE weakness type, lists affected products as CPE, and has package advisories with fixed versions">
        <defs>
          <marker id="dg-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M0 0L10 5L0 10z" className="dg-arrowhead" />
          </marker>
        </defs>
        <Box x={235} y={95} w={170} title="CVE" lines={["one concrete flaw", "CVE-2021-44228"]} />
        <Box x={235} y={8} w={170} title="Scores" lines={["CVSS · EPSS · KEV"]} />
        <Box x={10} y={95} w={170} title="CWE" lines={["the kind of mistake", "CWE-502"]} />
        <Box x={460} y={20} w={170} title="CPE" lines={["affected product", "cpe:2.3:a:apache:log4j"]} />
        <Box x={460} y={150} w={170} title="Package advisory" lines={["package + versions", "introduced → fixed"]} />
        <line x1={235} y1={125} x2={182} y2={125} className="dg-line" markerEnd="url(#dg-arrow)" />
        <text x={208} y={116} textAnchor="middle" className="dg-label">type</text>
        <line x1={320} y1={95} x2={320} y2={65} className="dg-line" markerEnd="url(#dg-arrow)" />
        <line x1={405} y1={110} x2={458} y2={70} className="dg-line" markerEnd="url(#dg-arrow)" />
        <text x={445} y={104} textAnchor="middle" className="dg-label">affects</text>
        <line x1={405} y1={140} x2={458} y2={175} className="dg-line" markerEnd="url(#dg-arrow)" />
        <text x={445} y={168} textAnchor="middle" className="dg-label">alias</text>
      </svg>
      <figcaption>The CVE is the center. The CWE is its type; CPE and package advisories say what is affected, in the form that product or package users need.</figcaption>
    </figure>
  );
}

/**
 * Diagrams that topics can embed with a fenced block:
 *
 *     ```diagram
 *     name
 *     ```
 *
 * They are React components (SVG/HTML), so they follow the light and dark theme.
 */
export const DIAGRAMS: Record<string, ComponentType> = {
  "severity-scale": SeverityScale,
  "cvss-vector": CvssVectorBreakdown,
  "cve-cwe-cpe": CveCweCpe,
};
