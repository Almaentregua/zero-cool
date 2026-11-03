import { render, screen } from "@testing-library/react";
import { afterEach, vi } from "vitest";

import App from "./App";

afterEach(() => vi.unstubAllGlobals());

test("shows ok when the API health check succeeds", async () => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true }));
  render(<App />);
  expect(await screen.findByText("API status: ok")).toBeInTheDocument();
});

test("shows error when the API is unreachable", async () => {
  vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("down")));
  render(<App />);
  expect(await screen.findByText("API status: error")).toBeInTheDocument();
});
