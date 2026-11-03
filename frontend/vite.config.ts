import react from "@vitejs/plugin-react";
import { loadEnv } from "vite";
import { defineConfig } from "vitest/config";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  return {
    plugins: [react()],
    test: {
      environment: "jsdom",
      globals: true,
      setupFiles: "./src/test-setup.ts",
    },
    server: {
      // Proxy API calls so the browser sees a single origin in development.
      proxy: { "/api": env.VITE_API_URL ?? "http://localhost:8000" },
    },
  };
});
