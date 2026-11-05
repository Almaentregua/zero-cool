import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";

import type { Change, ReportDetail, ReportSummary, SourceResult } from "./api";
import App from "./App";
import { describeChange } from "./reportFormat";

function block(overrides: Partial<SourceResult> = {}): SourceResult {
  return {
    source: "epss",
    source_name: "EPSS (FIRST)",
    cve_id: "CVE-2021-44228",
    status: "ok",
    message: null,
    origin_url: "https://api.first.org/data/v1/epss?cve=CVE-2021-44228",
    retrieved_at: "2026-11-04T15:00:12Z",
    data: { score: 0.94, percentile: 0.99 },
    ...overrides,
  };
}

const NOTES = "# Plan\n\n- check **patches**\n\n<script>alert(1)</script>\n\n[bad](javascript:alert(1)) [good](https://example.test/x)\n\n![pic](https://evil.test/p.png)";

function makeReport(overrides: Partial<ReportDetail> = {}): ReportDetail {
  return {
    id: 7,
    title: "Log4Shell",
    status: "open",
    cves: ["CVE-2021-44228"],
    created_at: "2026-11-04T14:00:00Z",
    updated_at: "2026-11-04T15:00:00Z",
    notes: NOTES,
    results: [
      block(),
      block({
        source: "osv",
        source_name: "OSV / GitHub Advisories",
        status: "no_data",
        message: "No advisory in the local database",
        data: null,
      }),
    ],
    ...overrides,
  };
}

type Handler = (url: string, init?: RequestInit) => unknown;

/** A non-200 answer for `mockApi`. */
const http = (status: number, body?: unknown) => ({ __http: status, body });

/** Mocks fetch; a handler returns a body or `http(status, body)`. */
function mockApi(handler: Handler) {
  const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
    const out = handler(url, init) as { __http?: number; body?: unknown } | undefined;
    const special = out !== null && typeof out === "object" && "__http" in out;
    const status = special ? (out.__http ?? 200) : 200;
    const body = special ? out.body : out;
    return { ok: status < 400, status, json: async () => body } as Response;
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

beforeEach(() => localStorage.clear());
afterEach(() => vi.unstubAllGlobals());

test("report list shows saved reports and links to them", async () => {
  const items: ReportSummary[] = [
    { id: 7, title: "Log4Shell <b>x</b>", status: "done", cves: ["CVE-2021-44228"], created_at: "2026-11-04T14:00:00Z", updated_at: "2026-11-04T15:00:00Z" },
  ];
  mockApi(() => items);
  renderAt("/reports");
  const link = await screen.findByRole("link", { name: "Log4Shell <b>x</b>" });
  expect(link).toHaveAttribute("href", "/reports/7");
  expect(screen.getByText("Done")).toBeInTheDocument();
});

test("empty report list explains how to start", async () => {
  mockApi(() => []);
  renderAt("/reports");
  expect(await screen.findByText("No reports yet.")).toBeInTheDocument();
});

test("a report shows its snapshot: one labelled block per source with status and origin", async () => {
  mockApi(() => makeReport());
  renderAt("/reports/7");
  expect(await screen.findByRole("heading", { name: "Log4Shell" })).toBeInTheDocument();
  const region = screen.getByRole("region", { name: "CVE-2021-44228" });
  expect(within(region).getByText("Sources consulted (2)")).toBeInTheDocument();
  const epss = within(region).getByRole("heading", { name: "EPSS (FIRST)" }).closest("article")!;
  expect(within(epss).getByText("Retrieved: 2026-11-04 15:00 UTC", { exact: false })).toBeInTheDocument();
  expect(within(epss).getByText("94.0%")).toBeInTheDocument();
  const osv = within(region).getByRole("heading", { name: "OSV / GitHub Advisories" }).closest("article")!;
  expect(within(osv).getByText("No data")).toBeInTheDocument();
  expect(within(osv).getByText("No advisory in the local database")).toBeInTheDocument();
});

test("a missing report says so", async () => {
  mockApi(() => http(404, { detail: "Report 9 not found" }));
  renderAt("/reports/9");
  expect(await screen.findByRole("alert")).toHaveTextContent("This report does not exist.");
});

test("Markdown notes are rendered safely: no raw HTML, no javascript links, no remote images", async () => {
  mockApi(() => makeReport());
  const { container } = renderAt("/reports/7");
  expect(await screen.findByRole("heading", { name: "Plan" })).toBeInTheDocument();
  const notes = container.querySelector(".notes-markdown")!;
  expect(within(notes as HTMLElement).getByText("patches").tagName).toBe("STRONG");
  expect(notes.querySelector("script")).toBeNull();
  expect(notes.textContent).not.toContain("alert(1)</script>");
  expect(within(notes as HTMLElement).getByText("bad").closest("a")).toBeNull();
  const good = within(notes as HTMLElement).getByRole("link", { name: "good" });
  expect(good).toHaveAttribute("href", "https://example.test/x");
  expect(good).toHaveAttribute("rel", "noopener noreferrer");
  expect(notes.querySelector("img")).toBeNull();
  expect(notes).toHaveTextContent("[image: pic]");
});

test("plain text mode shows the notes exactly as typed and is remembered", async () => {
  mockApi(() => makeReport());
  const { container } = renderAt("/reports/7");
  await screen.findByRole("heading", { name: "Plan" });
  await userEvent.click(screen.getByLabelText("Plain text"));
  const pre = container.querySelector("pre.notes-plain")!;
  expect(pre.textContent).toBe(NOTES);
  expect(container.querySelector(".notes-markdown")).toBeNull();
  expect(localStorage.getItem("notes-mode")).toBe("plain");
});

test("the remembered mode is used when opening a report", async () => {
  localStorage.setItem("notes-mode", "plain");
  mockApi(() => makeReport());
  const { container } = renderAt("/reports/7");
  await screen.findByRole("heading", { name: "Log4Shell" });
  expect(container.querySelector("pre.notes-plain")).not.toBeNull();
  expect(screen.getByLabelText("Plain text")).toBeChecked();
});

test("editing notes sends only the notes and shows the saved result", async () => {
  const fetchMock = mockApi((_url, init) =>
    init?.method === "PATCH" ? makeReport({ notes: "new **text**" }) : makeReport(),
  );
  renderAt("/reports/7");
  await userEvent.click(await screen.findByRole("button", { name: "Edit notes" }));
  const box = screen.getByLabelText("Notes (Markdown)");
  await userEvent.clear(box);
  await userEvent.type(box, "new **text**");
  await userEvent.click(screen.getByRole("button", { name: "Save notes" }));
  expect(await screen.findByRole("button", { name: "Edit notes" })).toBeInTheDocument();
  const call = fetchMock.mock.calls.find(([, init]) => init?.method === "PATCH")!;
  expect(call[0]).toBe("/api/reports/7");
  expect(JSON.parse(call[1]!.body as string)).toEqual({ notes: "new **text**" });
  expect(screen.getByText("text").tagName).toBe("STRONG");
});

test("cancelling an edit keeps the saved notes", async () => {
  const fetchMock = mockApi(() => makeReport());
  renderAt("/reports/7");
  await userEvent.click(await screen.findByRole("button", { name: "Edit notes" }));
  await userEvent.type(screen.getByLabelText("Notes (Markdown)"), "zzz");
  await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
  expect(screen.queryByText(/zzz/)).toBeNull();
  expect(fetchMock.mock.calls.some(([, init]) => init?.method === "PATCH")).toBe(false);
});

test("adding CVEs validates the ids first and then sends them", async () => {
  const fetchMock = mockApi((_url, init) => (init?.method === "PATCH" ? makeReport({ cves: ["CVE-2021-44228", "CVE-2022-22965"] }) : makeReport()));
  renderAt("/reports/7");
  const input = await screen.findByLabelText("Add CVEs");
  await userEvent.type(input, "nope");
  await userEvent.click(screen.getByRole("button", { name: "Add and investigate" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("nope");
  expect(fetchMock.mock.calls.some(([, init]) => init?.method === "PATCH")).toBe(false);
  await userEvent.clear(input);
  await userEvent.type(input, "cve-2022-22965");
  await userEvent.click(screen.getByRole("button", { name: "Add and investigate" }));
  await screen.findByRole("link", { name: "CVE-2022-22965" });
  const call = fetchMock.mock.calls.find(([, init]) => init?.method === "PATCH")!;
  expect(JSON.parse(call[1]!.body as string)).toEqual({ add_cves: ["CVE-2022-22965"] });
});

test("the last CVE of a report cannot be removed", async () => {
  mockApi(() => makeReport());
  renderAt("/reports/7");
  expect(await screen.findByRole("button", { name: "Remove CVE-2021-44228" })).toBeDisabled();
});

test("refresh lists what changed, including failures that kept old data", async () => {
  const changes: Change[] = [
    { cve_id: "CVE-2021-44228", source: "epss", source_name: "EPSS (FIRST)", kind: "data", before_status: "ok", after_status: "ok", fields: ["score"] },
    { cve_id: "CVE-2021-44228", source: "osv", source_name: "OSV / GitHub Advisories", kind: "refresh_failed", before_status: "no_data", after_status: "error", fields: [] },
  ];
  const fetchMock = mockApi((url) => (url.endsWith("/refresh") ? { report: makeReport(), changes } : makeReport()));
  renderAt("/reports/7");
  await userEvent.click(await screen.findByRole("button", { name: "Refresh from the sources" }));
  const panel = await screen.findByRole("region", { name: "Changes since the last snapshot" });
  expect(within(panel).getByText("EPSS (FIRST) (CVE-2021-44228): changed score")).toBeInTheDocument();
  expect(within(panel).getByText(/could not be refreshed, the previous data was kept/)).toBeInTheDocument();
  expect(fetchMock).toHaveBeenCalledWith("/api/reports/7/refresh", expect.objectContaining({ method: "POST" }));
});

test("a refresh without changes says so", async () => {
  mockApi((url) => (url.endsWith("/refresh") ? { report: makeReport(), changes: [] } : makeReport()));
  renderAt("/reports/7");
  await userEvent.click(await screen.findByRole("button", { name: "Refresh from the sources" }));
  expect(await screen.findByText(/Nothing changed/)).toBeInTheDocument();
});

test("marking as done sends the status", async () => {
  const fetchMock = mockApi((_url, init) => (init?.method === "PATCH" ? makeReport({ status: "done" }) : makeReport()));
  renderAt("/reports/7");
  await userEvent.click(await screen.findByRole("button", { name: "Mark as done" }));
  expect(await screen.findByRole("button", { name: "Reopen" })).toBeInTheDocument();
  const call = fetchMock.mock.calls.find(([, init]) => init?.method === "PATCH")!;
  expect(JSON.parse(call[1]!.body as string)).toEqual({ status: "done" });
});

test("deleting asks for confirmation and returns to the list", async () => {
  const confirm = vi.spyOn(window, "confirm").mockReturnValueOnce(false).mockReturnValueOnce(true);
  const fetchMock = mockApi((url, init) => {
    if (init?.method === "DELETE") return http(204);
    return url === "/api/reports" ? [] : makeReport();
  });
  renderAt("/reports/7");
  const del = await screen.findByRole("button", { name: "Delete" });
  await userEvent.click(del);
  expect(fetchMock.mock.calls.some(([, init]) => init?.method === "DELETE")).toBe(false);
  await userEvent.click(del);
  expect(await screen.findByRole("heading", { name: "Reports" })).toBeInTheDocument();
  expect(confirm).toHaveBeenCalledTimes(2);
});

test("an API error is shown without losing the report", async () => {
  mockApi((_url, init) => (init?.method === "PATCH" ? http(422, { detail: "A report needs between 1 and 10 CVEs" }) : makeReport()));
  renderAt("/reports/7");
  await userEvent.click(await screen.findByRole("button", { name: "Mark as done" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("A report needs between 1 and 10 CVEs");
  expect(screen.getByRole("heading", { name: "Log4Shell" })).toBeInTheDocument();
});

test("saving an investigation creates the report and opens it", async () => {
  const fetchMock = mockApi((url, init) => {
    if (init?.method === "POST") return http(201, makeReport());
    if (url.startsWith("/api/research/")) {
      return { cve_id: "CVE-2021-44228", generated_at: "2026-11-04T15:00:12Z", sources: [], results: [] };
    }
    return makeReport();
  });
  renderAt("/investigations?cves=CVE-2021-44228");
  await userEvent.type(await screen.findByLabelText("Report title"), "  My case ");
  await userEvent.click(screen.getByRole("button", { name: "Save as report" }));
  expect(await screen.findByRole("link", { name: "← Back to reports" })).toBeInTheDocument();
  const call = fetchMock.mock.calls.find(([, init]) => init?.method === "POST")!;
  expect(call[0]).toBe("/api/reports");
  expect(JSON.parse(call[1]!.body as string)).toEqual({ title: "My case", cves: ["CVE-2021-44228"] });
});

test("describeChange covers every kind of change", () => {
  const base = { cve_id: "CVE-1-1", source: "x", source_name: "X", fields: [] as string[] };
  expect(describeChange({ ...base, kind: "new", before_status: null, after_status: "ok" })).toBe("X (CVE-1-1): added");
  expect(describeChange({ ...base, kind: "status", before_status: "no_data", after_status: "ok" })).toBe("X (CVE-1-1): No data → Has data");
});
