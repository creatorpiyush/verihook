import { existsSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import pkg from "../package.json";

const jsr = JSON.parse(readFileSync("jsr.json", "utf8")) as {
  version: string;
  exports: Record<string, string>;
};

describe("jsr.json", () => {
  it("has the same version as package.json", () => {
    expect(jsr.version).toBe(pkg.version);
  });

  it("exposes the same subpaths as package.json", () => {
    const npmSubpaths = Object.keys(pkg.exports).filter(
      (key) => key !== "./package.json",
    );
    expect(Object.keys(jsr.exports).sort()).toEqual(npmSubpaths.sort());
  });

  it("points every subpath at an existing source file", () => {
    for (const file of Object.values(jsr.exports)) {
      expect(existsSync(file), file).toBe(true);
    }
  });
});
