import { defineConfig } from "vitest/config";

/** Unit tests next to the sources, integration tests against the in-process mock provider in `test/`. */
export default defineConfig({
  test: {
    include: ["src/**/*.test.ts", "test/**/*.test.ts"],
    environment: "node",
    restoreMocks: true,
  },
});
