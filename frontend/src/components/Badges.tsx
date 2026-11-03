import type { Severity } from "../api";
import { NOT_AVAILABLE } from "../format";

export function SeverityBadge({ severity }: { severity: Severity | null }) {
  if (severity === null) return <span className="muted">{NOT_AVAILABLE}</span>;
  return <span className={`badge sev-${severity.toLowerCase()}`}>{severity}</span>;
}

export function YesNo({ value, yesClass }: { value: boolean | null; yesClass?: string }) {
  if (value === null) return <span className="muted">{NOT_AVAILABLE}</span>;
  return <span className={value ? `badge ${yesClass ?? "flag"}` : "muted"}>{value ? "Yes" : "No"}</span>;
}
