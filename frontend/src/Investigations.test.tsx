import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";

import type { ResearchResponse, SourceResult } from "./api";
import App from "./App";
import { parseCveIds } from "./format";

function result(overrides: Partial<SourceResult>): SourceResult {
  return {
    source: "nvd",
    source_name: "NVD (NIST)",
    cve_id: "CVE-2021-44228",
    status: "ok",
    message: null,
    origin_url: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
    retrieved_at: "2026-11-04T15:00:12Z",
    data: null,
    ...overrides,
  };
}

const research: ResearchResponse = {
  cve_id: "CVE-2021-44228",
  generated_at: "2026-11-04T15:00:12Z",
  sources: [
    { source: "kev", source_name: "CISA KEV", status: "ok" },
    { source: "nvd", source_name: "NVD (NIST)", status: "ok" },
    { source: "osv", source_name: "OSV / GitHub Advisories", status: "no_data" },
    { source: "epss", source_name: "EPSS (FIRST)", status: "error" },
  ],
  results: [
    result({
      source: "kev",
      source_name: "CISA KEV",
      origin_url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
      data: { in_kev: true, vendor: "Apache", product: "Log4j2", date_added: "2021-12-10", ransomware_use: null },
    }),
    result({
      data: {
        description: "<img src=x onerror=alert(1)> Log4j",
        cvss_score: 10,
        severity: "CRITICAL",
        cvss_vector: null,
        references: ["https://logging.apache.org/", "javascript:alert(1)"],
      },
    }),
    result({
      source: "osv",
      source_name: "OSV / GitHub Advisories",
      status: "no_data",
      message: "No advisory for Maven or npm packages in the local database",
      origin_url: "javascript:alert(1)",
    }),
    result({
      source: "epss",
      source_name: "EPSS (FIRST)",
      status: "error",
      message: "The source did not answer within 15 s",
      origin_url: null,
    }),
  ],
};

function mockApi() {
  const fetchMock = vi.fn(async (url: string) => {
    const id = url.split("/api/research/")[1].split("?")[0];
    const body = { ...research, cve_id: id, results: research.results.map((r) => ({ ...r, cve_id: id })) };
    return { ok: true, status: 200, json: async () => body } as Response;
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <App />
    </MemoryRouter>,
  );
}

afterEach(() => vi.unstubAllGlobals());

test("parseCveIds normalizes, de-duplicates and reports invalid tokens", () => {
  expect(parseCveIds(" cve-2021-44228, CVE-2021-44228;CVE-2022-22965 nope CVE-1-1 ")).toEqual({
    valid: ["CVE-2021-44228", "CVE-2022-22965"],
    invalid: ["nope", "CVE-1-1"],
  });
});

test("navigation reaches the investigations page", async () => {
  mockApi();
  renderAt("/advisories");
  await userEvent.click(screen.getByRole("link", { name: "Investigations" }));
  expect(await screen.findByRole("heading", { name: "Investigations" })).toBeInTheDocument();
});

test("typing a CVE queries it and shows one labelled block per source", async () => {
  const fetchMock = mockApi();
  renderAt("/investigations");
  expect(screen.getByRole("button", { name: "Investigate" })).toBeDisabled();
  await userEvent.type(screen.getByLabelText(/CVE ids/), "cve-2021-44228");
  await userEvent.click(screen.getByRole("button", { name: "Investigate" }));

  expect(await screen.findByRole("heading", { name: "NVD (NIST)" })).toBeInTheDocument();
  expect(fetchMock).toHaveBeenCalledWith("/api/research/CVE-2021-44228", expect.anything());

  const summary = screen.getByRole("navigation", { name: /Sources consulted/ });
  expect(within(summary).getByText("Sources consulted (4)")).toBeInTheDocument();
  expect(within(summary).getByText("Error")).toBeInTheDocument();
  expect(within(summary).getByText("No data")).toBeInTheDocument();

  const nvd = screen.getByRole("heading", { name: "NVD (NIST)" }).closest("article")!;
  expect(within(nvd).getByText(/Retrieved: 2026-11-04 15:00 UTC/)).toBeInTheDocument();
  expect(within(nvd).getByRole("link", { name: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228" })).toBeInTheDocument();
  expect(within(nvd).getByText("Not available", { selector: "span.muted" })).toBeInTheDocument(); // CVSS vector
});

test("external text is never rendered as HTML and unsafe links are not links", async () => {
  mockApi();
  renderAt("/investigations?cves=CVE-2021-44228");
  const nvd = (await screen.findByRole("heading", { name: "NVD (NIST)" })).closest("article")!;
  expect(within(nvd).getByText(/<img src=x onerror=alert\(1\)> Log4j/)).toBeInTheDocument();
  expect(nvd.querySelector("img")).toBeNull();
  expect(within(nvd).getByRole("link", { name: "https://logging.apache.org/" })).toBeInTheDocument();
  expect(within(nvd).getByText("javascript:alert(1)").closest("a")).toBeNull();
  const osv = screen.getByRole("heading", { name: "OSV / GitHub Advisories" }).closest("article")!;
  expect(within(osv).queryByRole("link", { name: /javascript/ })).toBeNull();
});

test("sources with no data or an error say why, with their own status", async () => {
  mockApi();
  renderAt("/investigations?cves=CVE-2021-44228");
  const osv = (await screen.findByRole("heading", { name: "OSV / GitHub Advisories" })).closest("article")!;
  expect(within(osv).getByText("No data")).toBeInTheDocument();
  expect(within(osv).getByText(/No advisory for Maven or npm/)).toBeInTheDocument();
  const epss = screen.getByRole("heading", { name: "EPSS (FIRST)" }).closest("article")!;
  expect(within(epss).getByText("Error")).toBeInTheDocument();
  expect(within(epss).getByText(/did not answer within 15 s/)).toBeInTheDocument();
});

test("several CVEs get their own sections; invalid ids are reported and not queried", async () => {
  const fetchMock = mockApi();
  renderAt("/investigations?cves=CVE-2021-44228,CVE-2022-22965,nope");
  expect(await screen.findByRole("region", { name: "CVE-2022-22965" })).toBeInTheDocument();
  expect(screen.getByRole("region", { name: "CVE-2021-44228" })).toBeInTheDocument();
  expect(screen.getByRole("alert")).toHaveTextContent("nope");
  expect(fetchMock).toHaveBeenCalledTimes(2);
});

test("refresh asks the API to bypass its cache", async () => {
  const fetchMock = mockApi();
  renderAt("/investigations?cves=CVE-2021-44228");
  await userEvent.click(await screen.findByRole("button", { name: "Refresh from the sources" }));
  expect(fetchMock).toHaveBeenLastCalledWith("/api/research/CVE-2021-44228?refresh=true", expect.anything());
});

test("a failing request shows an error instead of crashing", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => ({ ok: false, status: 500, json: async () => ({}) }) as Response),
  );
  renderAt("/investigations?cves=CVE-2021-44228");
  expect(await screen.findByRole("alert")).toHaveTextContent("Could not investigate CVE-2021-44228");
});
