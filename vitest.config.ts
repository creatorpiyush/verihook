import { defineConfig } from "vitest/config";
import pkg from "./package.json";

export default defineConfig({
  define: {
    __VERIHOOK_VERSION__: JSON.stringify(pkg.version),
  },
  test: {
    globals: true,
    environment: "node",
    coverage: {
      provider: "v8",
      reporter: ["text", "json", "json-summary", "html"],
      include: ["src/**/*.ts"],
      exclude: ["src/index.ts", "src/express.ts", "src/next.ts"],
    },
  },
});
