/** Display helpers. Missing data is always shown as "Not available". */

export const NOT_AVAILABLE = "Not available";

export function formatScore(value: number | null): string {
  return value === null ? NOT_AVAILABLE : value.toFixed(1);
}

/** EPSS is a probability from 0 to 1, shown as a percentage. */
export function formatEpss(value: number | null): string {
  if (value === null) return NOT_AVAILABLE;
  const percent = value * 100;
  return `${percent < 0.1 && percent > 0 ? "<0.1" : percent.toFixed(1)}%`;
}

export function formatDate(value: string | null): string {
  return value === null ? NOT_AVAILABLE : value.slice(0, 10);
}

export function formatText(value: string | null): string {
  return value === null || value === "" ? NOT_AVAILABLE : value;
}

export function formatYesNo(value: boolean | null): string {
  if (value === null) return NOT_AVAILABLE;
  return value ? "Yes" : "No";
}

/**
 * Returns the URL only if it is http(s); anything else (javascript:, data:, ...)
 * returns null so it is never used as a link target.
 */
export function safeUrl(value: string): string | null {
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:" ? url.href : null;
  } catch {
    return null;
  }
}

/**
 * Describes one OSV version range as plain text without interpreting it, e.g.
 * "introduced 2.13.0 → fixed 2.15.0". Version ordering differs between Maven and npm,
 * so the app only repeats what the source reports.
 */
export function describeRange(range: { events?: Record<string, string>[] }): string {
  const parts = (range.events ?? []).flatMap((event) =>
    Object.entries(event).map(([kind, version]) => `${kind.replace(/_/g, " ")} ${version}`),
  );
  return parts.length > 0 ? parts.join(" → ") : NOT_AVAILABLE;
}

/** "2026-11-04T15:00:12Z" -> "2026-11-04 15:00 UTC". Returns "Not available" for null. */
export function formatDateTime(value: string | null): string {
  if (value === null) return NOT_AVAILABLE;
  return `${value.slice(0, 10)} ${value.slice(11, 16)} UTC`;
}

const CVE_ID = /^CVE-\d{4}-\d{4,}$/;

/**
 * Splits text typed by the user into CVE ids (separated by spaces, commas or semicolons).
 * Ids are upper-cased and de-duplicated; anything that is not a CVE id goes to `invalid`.
 */
export function parseCveIds(text: string): { valid: string[]; invalid: string[] } {
  const valid: string[] = [];
  const invalid: string[] = [];
  for (const token of text.split(/[\s,;]+/).filter(Boolean)) {
    const id = token.toUpperCase();
    if (CVE_ID.test(id)) {
      if (!valid.includes(id)) valid.push(id);
    } else {
      invalid.push(token.slice(0, 30));
    }
  }
  return { valid, invalid };
}
