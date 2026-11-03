/** Types and calls for the backend API. See docs/technical/api.md. */

export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export const SEVERITIES: Severity[] = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];

/** Every nullable field means "not available": no source provided it. */
export interface VulnerabilitySummary {
  cve_id: string;
  title: string | null;
  vendor: string | null;
  product: string | null;
  cvss_score: number | null;
  severity: Severity | null;
  epss_score: number | null;
  epss_percentile: number | null;
  is_kev: boolean;
  ransomware_use: boolean | null;
  date_added: string | null;
  technologies: string[];
}

export interface VulnerabilityDetail extends VulnerabilitySummary {
  description: string | null;
  cvss_vector: string | null;
  published_at: string | null;
  modified_at: string | null;
  kev_due_date: string | null;
  references: string[];
}

export interface VulnerabilityPage {
  items: VulnerabilitySummary[];
  total: number;
  page: number;
  page_size: number;
}

export interface Technology {
  name: string;
  osv_ecosystems: string[];
  products: string[];
}

/** Error carrying the HTTP status so pages can tell "not found" from "down". */
export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

/** Query parameters that the list page keeps in the URL (and sends to the API). */
export const LIST_PARAMS = [
  "q",
  "technology",
  "added_from",
  "added_to",
  "severity",
  "min_cvss",
  "min_epss",
  "ransomware",
  "sort",
  "order",
  "page",
] as const;

/** Keep only known, non-empty parameters; `severity` may repeat. */
export function cleanListParams(source: URLSearchParams): URLSearchParams {
  const clean = new URLSearchParams();
  for (const key of LIST_PARAMS) {
    for (const value of source.getAll(key)) {
      if (value.trim() !== "") clean.append(key, value.trim());
    }
  }
  return clean;
}

async function getJson<T>(url: string, signal?: AbortSignal): Promise<T> {
  const response = await fetch(url, { signal });
  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    try {
      const body = await response.json();
      if (typeof body?.detail === "string") message = body.detail;
    } catch {
      // body was not JSON; keep the generic message
    }
    throw new ApiError(message, response.status);
  }
  return (await response.json()) as T;
}

export function fetchVulnerabilities(params: URLSearchParams, signal?: AbortSignal) {
  const query = cleanListParams(params).toString();
  return getJson<VulnerabilityPage>(`/api/vulnerabilities${query ? `?${query}` : ""}`, signal);
}

export function fetchVulnerability(cveId: string, signal?: AbortSignal) {
  return getJson<VulnerabilityDetail>(`/api/vulnerabilities/${encodeURIComponent(cveId)}`, signal);
}

export function fetchTechnologies(signal?: AbortSignal) {
  return getJson<Technology[]>("/api/technologies", signal);
}
