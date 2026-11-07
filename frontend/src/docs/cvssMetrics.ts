/** Meaning of the CVSS 3.1 base metrics, used by the interactive vector diagram. */

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

/** Explains one `KEY:VALUE` part of a CVSS 3.1 vector, or null when the part is unknown. */
export function describeVectorPart(part: string): { name: string; meaning: string } | null {
  const [key, value] = part.split(":");
  const metric = METRICS[key];
  const meaning = metric?.values[value];
  return metric && meaning ? { name: metric.name, meaning } : null;
}
