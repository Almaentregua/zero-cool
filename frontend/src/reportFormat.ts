import type { Change, SourceStatus } from "./api";

export const STATUS_LABEL: Record<SourceStatus, string> = {
  ok: "Has data",
  no_data: "No data",
  error: "Error",
};

/** One line describing what a refresh changed. */
export function describeChange(c: Change): string {
  const where = `${c.source_name} (${c.cve_id})`;
  switch (c.kind) {
    case "new":
      return `${where}: added`;
    case "status":
      return `${where}: ${c.before_status ? STATUS_LABEL[c.before_status] : "-"} → ${STATUS_LABEL[c.after_status]}`;
    case "data":
      return `${where}: changed ${c.fields.join(", ")}`;
    case "refresh_failed":
      return `${where}: could not be refreshed, the previous data was kept`;
  }
}
