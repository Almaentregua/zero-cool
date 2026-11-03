import { ApiError, cleanListParams, fetchVulnerabilities, fetchVulnerability } from "./api";

afterEach(() => vi.unstubAllGlobals());

test("cleanListParams keeps known non-empty params and repeated severities", () => {
  const clean = cleanListParams(new URLSearchParams("q= log4j &junk=1&min_cvss=&severity=HIGH&severity=CRITICAL"));
  expect(clean.toString()).toBe("q=log4j&severity=HIGH&severity=CRITICAL");
});

test("fetchVulnerabilities sends only clean params", async () => {
  const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ items: [] }) });
  vi.stubGlobal("fetch", fetchMock);
  await fetchVulnerabilities(new URLSearchParams("q=a&junk=1"));
  expect(fetchMock.mock.calls[0][0]).toBe("/api/vulnerabilities?q=a");
});

test("errors carry the API message and status", async () => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, status: 422, json: async () => ({ detail: "bad filter" }) }));
  await expect(fetchVulnerabilities(new URLSearchParams())).rejects.toMatchObject({ message: "bad filter", status: 422 });
});

test("non-JSON error bodies fall back to a generic message", async () => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, status: 502, json: async () => { throw new Error("x"); } }));
  const error = await fetchVulnerability("CVE-2021-44228").catch((e: unknown) => e);
  expect(error).toBeInstanceOf(ApiError);
  expect((error as ApiError).message).toBe("Request failed (502)");
});
