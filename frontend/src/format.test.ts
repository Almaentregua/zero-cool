import { NOT_AVAILABLE, formatDate, formatEpss, formatScore, formatText, formatYesNo, safeUrl } from "./format";

test("missing values are shown as not available, never as zero", () => {
  expect(formatScore(null)).toBe(NOT_AVAILABLE);
  expect(formatEpss(null)).toBe(NOT_AVAILABLE);
  expect(formatDate(null)).toBe(NOT_AVAILABLE);
  expect(formatText(null)).toBe(NOT_AVAILABLE);
  expect(formatText("")).toBe(NOT_AVAILABLE);
  expect(formatYesNo(null)).toBe(NOT_AVAILABLE);
});

test("real zero values are kept as zero", () => {
  expect(formatScore(0)).toBe("0.0");
  expect(formatEpss(0)).toBe("0.0%");
});

test("formats values", () => {
  expect(formatScore(9.8)).toBe("9.8");
  expect(formatEpss(0.97)).toBe("97.0%");
  expect(formatEpss(0.0004)).toBe("<0.1%");
  expect(formatDate("2021-12-10T10:15:09.143")).toBe("2021-12-10");
  expect(formatYesNo(true)).toBe("Yes");
  expect(formatYesNo(false)).toBe("No");
});

test("safeUrl only allows http and https", () => {
  expect(safeUrl("https://example.test/a")).toBe("https://example.test/a");
  expect(safeUrl("http://example.test")).toBe("http://example.test/");
  expect(safeUrl("javascript:alert(1)")).toBeNull();
  expect(safeUrl("data:text/html,<script>1</script>")).toBeNull();
  expect(safeUrl("not a url")).toBeNull();
});
