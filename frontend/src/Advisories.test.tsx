import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";

import type { AdvisoryDetail, AdvisoryPage, AdvisorySummary, VulnerabilityDetail } from "./api";
import { cleanAdvisoryParams } from "./api";
import App from "./App";
import { describeRange } from "./format";

const log4j: AdvisorySummary = {
  id: "GHSA-jfh8-c2jp-5v3q",
  summary: "Remote code injection <b>in</b> Log4j",
  severity: "CRITICAL",
  epss_score: 0.99,
  epss_percentile: 1,
  published_at: "2021-12-10T00:40:56",
  github_reviewed: true,
  cves: ["CVE-2021-44228"],
  packages: [
    { ecosystem: "Maven", name: "org.apache.logging.log4j:log4j-core" },
    { ecosystem: "Maven", name: "a:b" },
    { ecosystem: "Maven", name: "c:d" },
  ],
  technologies: ["Java"],
};

const noCve: AdvisorySummary = {
  ...log4j,
  id: "GHSA-aaaa-bbbb-cccc",
  summary: null,
  severity: null,
  epss_score: null,
  epss_percentile: null,
  cves: [],
  packages: [{ ecosystem: "npm", name: "lodash" }],
};

const detail: AdvisoryDetail = {
  id: log4j.id,
  summary: "Log4j",
  details: "<img src=x onerror=alert(1)> Markdown **text**",
  severity: "CRITICAL",
  cvss_vector: null,
  epss_score: 0.99,
  epss_percentile: 1,
  published_at: "2021-12-10T00:40:56",
  modified_at: null,
  github_reviewed: true,
  technologies: ["Java"],
  cves: [
    { cve_id: "CVE-2021-44228", in_database: true },
    { cve_id: "CVE-2021-9999", in_database: false },
  ],
  packages: [
    {
      ecosystem: "Maven",
      name: "org.apache.logging.log4j:log4j-core",
      fixed_versions: ["2.15.0"],
      ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "2.13.0" }, { fixed: "2.15.0" }] }],
    },
    { ecosystem: "Maven", name: "no.ranges:here", fixed_versions: [], ranges: [] },
  ],
  references: ["https://example.test/log4j", "javascript:alert(1)"],
};

const cveDetail: VulnerabilityDetail = {
  cve_id: "CVE-2021-44228",
  title: "Log4j",
  vendor: "Apache",
  product: "Log4j2",
  cvss_score: null,
  severity: null,
  epss_score: null,
  epss_percentile: null,
  is_kev: true,
  ransomware_use: null,
  date_added: "2021-12-10",
  technologies: ["Java"],
  description: null,
  cvss_vector: null,
  published_at: null,
  modified_at: null,
  kev_due_date: null,
  references: [],
  advisories: [
    {
      id: log4j.id,
      summary: "Remote code injection in Log4j",
      severity: "CRITICAL",
      packages: [{ ecosystem: "Maven", name: "org.apache.logging.log4j:log4j-core" }],
    },
  ],
};

function page(items: AdvisorySummary[], total = items.length): AdvisoryPage {
  return { items, total, page: 1, page_size: 25 };
}

function mockApi(overrides: Record<string, unknown> = {}) {
  const fetchMock = vi.fn(async (url: string) => {
    const path = url.split("?")[0];
    const body =
      overrides[url] ??
      overrides[path] ??
      (path === "/api/technologies"
        ? [{ name: "Java", osv_ecosystems: ["Maven"], products: [] }]
        : path === "/api/advisories"
          ? page([log4j, noCve])
          : path.startsWith("/api/advisories/")
            ? detail
            : path.startsWith("/api/vulnerabilities/")
              ? cveDetail
              : { items: [], total: 0, page: 1, page_size: 25 });
    if (typeof body === "object" && body !== null && "ok" in body && "json" in body) return body as Response;
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

test("navigation switches between KEV vulnerabilities and package advisories", async () => {
  mockApi();
  renderAt("/");
  await userEvent.click(screen.getByRole("link", { name: "Package advisories" }));
  expect(await screen.findByRole("heading", { name: "Package advisories" })).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Known exploited (KEV)" })).toBeInTheDocument();
});

test("advisory list shows rows, 'Not available' and a package summary", async () => {
  mockApi();
  renderAt("/advisories");
  const row = (await screen.findByRole("link", { name: log4j.id })).closest("tr")!;
  expect(within(row).getByText("99.0%")).toBeInTheDocument();
  expect(within(row).getByText("CRITICAL")).toBeInTheDocument();
  expect(within(row).getByText("+1 more")).toBeInTheDocument();
  expect(within(row).getByText("2021-12-10")).toBeInTheDocument();
  const empty = screen.getByRole("link", { name: noCve.id }).closest("tr")!;
  expect(within(empty).getAllByText("Not available").length).toBeGreaterThanOrEqual(4); // summary, severity, EPSS, CVE
  expect(screen.getByText("2 advisories found")).toBeInTheDocument();
});

test("external HTML in advisory summaries is rendered as text", async () => {
  mockApi();
  const { container } = renderAt("/advisories");
  expect(await screen.findByText("Remote code injection <b>in</b> Log4j")).toBeInTheDocument();
  expect(container.querySelector("tbody b")).toBeNull();
});

test("advisory filters in the URL are sent to the API, unknown ones dropped", async () => {
  const fetchMock = mockApi();
  renderAt("/advisories?technology=Java&severity=HIGH&has_cve=false&min_cvss=5&junk=x");
  await screen.findByRole("link", { name: log4j.id });
  const call = fetchMock.mock.calls.map((c) => c[0]).find((u) => u.startsWith("/api/advisories?"));
  expect(call).toBe("/api/advisories?technology=Java&severity=HIGH&has_cve=false");
});

test("applying the advisory form updates the request", async () => {
  const fetchMock = mockApi();
  renderAt("/advisories");
  await screen.findByRole("link", { name: log4j.id });
  await userEvent.type(screen.getByLabelText("Search"), "lodash");
  await userEvent.selectOptions(screen.getByLabelText("CVE"), "false");
  await userEvent.click(screen.getByLabelText("HIGH"));
  await userEvent.click(screen.getByRole("button", { name: "Apply" }));
  expect(fetchMock.mock.calls.map((c) => c[0])).toContain("/api/advisories?q=lodash&severity=HIGH&has_cve=false");
});

test("advisory list: pagination and sorting", async () => {
  const fetchMock = mockApi({ "/api/advisories": page([log4j], 60) });
  renderAt("/advisories");
  await screen.findByText("Page 1 of 3");
  await userEvent.click(screen.getByRole("button", { name: "Next" }));
  await userEvent.click(screen.getByRole("button", { name: "EPSS" }));
  const urls = fetchMock.mock.calls.map((c) => c[0]);
  expect(urls).toContain("/api/advisories?page=2");
  expect(urls).toContain("/api/advisories?sort=epss&order=desc"); // sorting goes back to page 1
});

test("advisory list shows empty and error messages", async () => {
  mockApi({ "/api/advisories": page([], 0) });
  const first = renderAt("/advisories?q=zzz");
  expect(await screen.findByText("No advisories match these filters.")).toBeInTheDocument();
  first.unmount();

  mockApi({ "/api/advisories": { ok: false, status: 500, json: async () => ({}) } });
  renderAt("/advisories");
  expect(await screen.findByRole("alert")).toHaveTextContent("Could not load advisories");
});

test("advisory detail shows packages as reported, links known CVEs and only safe references", async () => {
  mockApi();
  const { container } = renderAt("/advisory/GHSA-jfh8-c2jp-5v3q");
  expect(await screen.findByRole("heading", { name: log4j.id })).toBeInTheDocument();
  expect(screen.getByText("introduced 2.13.0 → fixed 2.15.0")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "CVE-2021-44228" })).toHaveAttribute("href", "/cve/CVE-2021-44228");
  expect(screen.queryByRole("link", { name: "CVE-2021-9999" })).toBeNull(); // not in the database: plain text
  expect(screen.getByText(/CVE-2021-9999/)).toBeInTheDocument();
  expect(screen.getByText("<img src=x onerror=alert(1)> Markdown **text**")).toBeInTheDocument();
  expect(container.querySelector("img")).toBeNull();
  expect(screen.getByRole("link", { name: "https://example.test/log4j" })).toHaveAttribute("rel", "noopener noreferrer");
  expect(screen.queryByRole("link", { name: "javascript:alert(1)" })).toBeNull();
  const noRanges = screen.getByText("no.ranges:here").closest("tr")!;
  expect(within(noRanges).getAllByText("Not available")).toHaveLength(2);
});

test("advisory detail explains a missing advisory", async () => {
  mockApi({
    "/api/advisories/GHSA-zzzz-zzzz-zzzz": { ok: false, status: 404, json: async () => ({ detail: "nope" }) },
  });
  renderAt("/advisory/GHSA-zzzz-zzzz-zzzz");
  expect(await screen.findByRole("alert")).toHaveTextContent("GHSA-zzzz-zzzz-zzzz is not in the database.");
});

test("back link from an advisory keeps the list filters", async () => {
  mockApi();
  renderAt("/advisories?technology=Java");
  await userEvent.click(await screen.findByRole("link", { name: log4j.id }));
  expect(await screen.findByRole("link", { name: /Back to advisories/ })).toHaveAttribute(
    "href",
    "/advisories?technology=Java",
  );
});

test("CVE page lists the related package advisories", async () => {
  mockApi();
  renderAt("/cve/CVE-2021-44228");
  const link = await screen.findByRole("link", { name: log4j.id });
  expect(link).toHaveAttribute("href", `/advisory/${log4j.id}`);
  expect(screen.getByText("Maven: org.apache.logging.log4j:log4j-core")).toBeInTheDocument();
});

test("CVE page says when no package advisory mentions it", async () => {
  mockApi({ "/api/vulnerabilities/CVE-2020-0001": { ...cveDetail, cve_id: "CVE-2020-0001", advisories: [] } });
  renderAt("/cve/CVE-2020-0001");
  expect(await screen.findByText("No Maven or npm package advisory mentions this CVE.")).toBeInTheDocument();
});

test("cleanAdvisoryParams keeps only advisory parameters", () => {
  const clean = cleanAdvisoryParams(new URLSearchParams("q=a&min_cvss=5&package=x&severity=LOW&severity=HIGH&has_cve="));
  expect(clean.toString()).toBe("q=a&package=x&severity=LOW&severity=HIGH");
});

test("describeRange repeats what the source reports without interpreting it", () => {
  expect(describeRange({ events: [{ introduced: "0" }, { last_affected: "1.2.3" }] })).toBe(
    "introduced 0 → last affected 1.2.3",
  );
  expect(describeRange({})).toBe("Not available");
});
