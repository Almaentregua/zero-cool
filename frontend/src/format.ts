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
