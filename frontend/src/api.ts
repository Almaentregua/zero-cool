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
  advisories: AdvisoryLink[];
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

export interface PackageRef {
  ecosystem: string;
  name: string;
}

/** An advisory related to a KEV vulnerability (shown on the CVE page). */
export interface AdvisoryLink {
  id: string;
  summary: string | null;
  severity: Severity | null;
  packages: PackageRef[];
}

export interface AdvisorySummary {
  id: string;
  summary: string | null;
  severity: Severity | null;
  epss_score: number | null;
  epss_percentile: number | null;
  published_at: string | null;
  github_reviewed: boolean | null;
  cves: string[];
  packages: PackageRef[];
  technologies: string[];
}

/** One OSV range, exactly as reported: events such as {"introduced": "2.0"} or {"fixed": "2.15.0"}. */
export interface OsvRange {
  type?: string;
  events?: Record<string, string>[];
}

export interface AdvisoryPackageDetail extends PackageRef {
  fixed_versions: string[];
  ranges: OsvRange[];
}

export interface AdvisoryDetail {
  id: string;
  summary: string | null;
  details: string | null;
  severity: Severity | null;
  cvss_vector: string | null;
  epss_score: number | null;
  epss_percentile: number | null;
  published_at: string | null;
  modified_at: string | null;
  github_reviewed: boolean | null;
  technologies: string[];
  cves: { cve_id: string; in_database: boolean }[];
  packages: AdvisoryPackageDetail[];
  references: string[];
}

export interface AdvisoryPage {
  items: AdvisorySummary[];
  total: number;
  page: number;
  page_size: number;
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

/** Query parameters of the advisory list page. */
export const ADVISORY_PARAMS = [
  "q",
  "technology",
  "package",
  "severity",
  "min_epss",
  "published_from",
  "published_to",
  "has_cve",
  "sort",
  "order",
  "page",
] as const;

/** Keep only the given known, non-empty parameters; `severity` may repeat. */
function cleanParams(source: URLSearchParams, keys: readonly string[]): URLSearchParams {
  const clean = new URLSearchParams();
  for (const key of keys) {
    for (const value of source.getAll(key)) {
      if (value.trim() !== "") clean.append(key, value.trim());
    }
  }
  return clean;
}

export function cleanListParams(source: URLSearchParams): URLSearchParams {
  return cleanParams(source, LIST_PARAMS);
}

export function cleanAdvisoryParams(source: URLSearchParams): URLSearchParams {
  return cleanParams(source, ADVISORY_PARAMS);
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

export function fetchAdvisories(params: URLSearchParams, signal?: AbortSignal) {
  const query = cleanAdvisoryParams(params).toString();
  return getJson<AdvisoryPage>(`/api/advisories${query ? `?${query}` : ""}`, signal);
}

export function fetchAdvisory(id: string, signal?: AbortSignal) {
  return getJson<AdvisoryDetail>(`/api/advisories/${encodeURIComponent(id)}`, signal);
}

export type SourceStatus = "ok" | "no_data" | "error";

/**
 * What one research source answered about one CVE. `data` is source specific and comes
 * from external sources: it is untrusted and must only be rendered as text.
 */
export interface SourceResult {
  source: string;
  source_name: string;
  cve_id: string;
  status: SourceStatus;
  message: string | null;
  origin_url: string | null;
  retrieved_at: string;
  data: Record<string, unknown> | null;
}

export interface ResearchResponse {
  cve_id: string;
  generated_at: string;
  sources: { source: string; source_name: string; status: SourceStatus }[];
  results: SourceResult[];
}

export function fetchResearch(cveId: string, refresh: boolean, signal?: AbortSignal) {
  const query = refresh ? "?refresh=true" : "";
  return getJson<ResearchResponse>(`/api/research/${encodeURIComponent(cveId)}${query}`, signal);
}
