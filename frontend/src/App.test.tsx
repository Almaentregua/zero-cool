import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";

import type { VulnerabilityDetail, VulnerabilityPage } from "./api";
import App from "./App";

const log4j = {
  cve_id: "CVE-2021-44228",
  title: "Log4j <b>RCE</b>",
  vendor: "Apache",
  product: "Log4j2",
  cvss_score: null,
  severity: null,
  epss_score: 0.97,
  epss_percentile: 1,
  is_kev: true,
  ransomware_use: true,
  date_added: "2021-12-10",
  technologies: ["Java"],
};

const detail: VulnerabilityDetail = {
  ...log4j,
  description: "<img src=x onerror=alert(1)> JNDI flaw",
  cvss_vector: null,
  published_at: null,
  modified_at: null,
  kev_due_date: "2021-12-24",
  references: ["https://example.test/advisory", "javascript:alert(1)"],
};

function listPage(items = [log4j], total = items.length): VulnerabilityPage {
  return { items, total, page: 1, page_size: 25 };
}

function isRawResponse(value: unknown): boolean {
  return typeof value === "object" && value !== null && "ok" in value && "json" in value;
}

function mockApi(overrides: Record<string, unknown> = {}) {
  const fetchMock = vi.fn(async (url: string) => {
    const path = url.split("?")[0];
    const body =
      overrides[url] ??
      overrides[path] ??
      (path === "/api/technologies"
        ? [{ name: "Java", osv_ecosystems: ["Maven"], products: ["Apache / Log4j2"] }]
        : path === "/api/vulnerabilities"
          ? listPage()
          : path.startsWith("/api/vulnerabilities/")
            ? detail
            : null);
    if (isRawResponse(body)) return body as Response;
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

test("list shows rows and 'Not available' for missing values", async () => {
  mockApi();
  renderAt("/");
  const row = (await screen.findByRole("link", { name: "CVE-2021-44228" })).closest("tr")!;
  expect(within(row).getAllByText("Not available").length).toBeGreaterThanOrEqual(2); // severity and CVSS
  expect(within(row).getByText("97.0%")).toBeInTheDocument();
  expect(within(row).getByText("Java")).toBeInTheDocument();
  expect(screen.getByText("1 vulnerability found")).toBeInTheDocument();
});

test("external HTML in titles is rendered as text, not as markup", async () => {
  mockApi();
  const { container } = renderAt("/");
  expect(await screen.findByText("Log4j <b>RCE</b>")).toBeInTheDocument();
  expect(container.querySelector("tbody b")).toBeNull();
});

test("filters in the URL are sent to the API", async () => {
  const fetchMock = mockApi();
  renderAt("/?technology=Java&severity=HIGH&severity=CRITICAL&min_epss=0.5&junk=x");
  await screen.findByRole("link", { name: "CVE-2021-44228" });
  const call = fetchMock.mock.calls.map((c) => c[0]).find((u) => u.startsWith("/api/vulnerabilities?"));
  expect(call).toBe("/api/vulnerabilities?technology=Java&severity=HIGH&severity=CRITICAL&min_epss=0.5");
});

test("applying the form updates the request", async () => {
  const fetchMock = mockApi();
  renderAt("/");
  await screen.findByRole("link", { name: "CVE-2021-44228" });
  await userEvent.type(screen.getByLabelText("Search"), "log4j");
  await userEvent.click(screen.getByLabelText("CRITICAL"));
  await userEvent.click(screen.getByLabelText("Used in ransomware"));
  await userEvent.click(screen.getByRole("button", { name: "Apply" }));
  const urls = fetchMock.mock.calls.map((c) => c[0]);
  expect(urls).toContain("/api/vulnerabilities?q=log4j&severity=CRITICAL&ransomware=true");
});

test("empty result shows a message", async () => {
  mockApi({ "/api/vulnerabilities": listPage([], 0) });
  renderAt("/?q=zzz");
  expect(await screen.findByText("No vulnerabilities match these filters.")).toBeInTheDocument();
});

test("API errors are shown to the user", async () => {
  mockApi({
    "/api/vulnerabilities": { ok: false, status: 500, json: async () => ({}) },
  });
  renderAt("/");
  expect(await screen.findByRole("alert")).toHaveTextContent("Could not load vulnerabilities");
});

test("pagination moves to the next page", async () => {
  const fetchMock = mockApi({ "/api/vulnerabilities": { items: [log4j], total: 60, page: 1, page_size: 25 } });
  renderAt("/");
  await screen.findByText("Page 1 of 3");
  await userEvent.click(screen.getByRole("button", { name: "Next" }));
  expect(fetchMock.mock.calls.map((c) => c[0])).toContain("/api/vulnerabilities?page=2");
});

test("sorting by a column toggles direction", async () => {
  const fetchMock = mockApi();
  renderAt("/");
  await screen.findByRole("link", { name: "CVE-2021-44228" });
  await userEvent.click(screen.getByRole("button", { name: "EPSS" }));
  await userEvent.click(screen.getByRole("button", { name: /EPSS/ }));
  const urls = fetchMock.mock.calls.map((c) => c[0]);
  expect(urls).toContain("/api/vulnerabilities?sort=epss&order=desc");
  expect(urls).toContain("/api/vulnerabilities?sort=epss&order=asc");
});

test("detail page shows fields, plain-text description and only safe links", async () => {
  mockApi();
  const { container } = renderAt("/cve/CVE-2021-44228");
  expect(await screen.findByRole("heading", { name: "CVE-2021-44228" })).toBeInTheDocument();
  expect(screen.getByText("<img src=x onerror=alert(1)> JNDI flaw")).toBeInTheDocument();
  expect(container.querySelector("img")).toBeNull();
  const safe = screen.getByRole("link", { name: "https://example.test/advisory" });
  expect(safe).toHaveAttribute("rel", "noopener noreferrer");
  expect(screen.queryByRole("link", { name: "javascript:alert(1)" })).toBeNull();
  expect(screen.getByText("javascript:alert(1)")).toBeInTheDocument(); // shown as text only
  expect(screen.getAllByText("Not available").length).toBeGreaterThan(0);
});

test("detail page explains a missing CVE", async () => {
  mockApi({
    "/api/vulnerabilities/CVE-1999-0001": { ok: false, status: 404, json: async () => ({ detail: "nope" }) },
  });
  renderAt("/cve/CVE-1999-0001");
  expect(await screen.findByRole("alert")).toHaveTextContent("CVE-1999-0001 is not in the database.");
});

test("back link keeps the list filters", async () => {
  mockApi();
  renderAt("/?technology=Java");
  await userEvent.click(await screen.findByRole("link", { name: "CVE-2021-44228" }));
  expect(await screen.findByRole("link", { name: /Back to list/ })).toHaveAttribute("href", "/?technology=Java");
});
