const esbuild = require("esbuild");
const { execSync } = require("node:child_process");

console.log("🔨 Building verihook distribution bundles...");

// 1. Build CJS bundles
esbuild.buildSync({
  entryPoints: {
    index: "src/index.ts",
    express: "src/express.ts",
    next: "src/next.ts",
    cli: "src/cli/index.ts",
  },
  outdir: "dist",
  bundle: true,
  format: "cjs",
  platform: "node",
  outExtension: { ".js": ".js" },
  sourcemap: true,
});

// 2. Build ESM bundles
esbuild.buildSync({
  entryPoints: {
    index: "src/index.ts",
    express: "src/express.ts",
    next: "src/next.ts",
    cli: "src/cli/index.ts",
  },
  outdir: "dist",
  bundle: true,
  format: "esm",
  platform: "node",
  outExtension: { ".js": ".mjs" },
  sourcemap: true,
});

// 3. Generate TypeScript declaration files (.d.ts)
execSync("./node_modules/.bin/tsc --emitDeclarationOnly --outDir dist", {
  stdio: "inherit",
});

console.log("✅ Build completed successfully!");
