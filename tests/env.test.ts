import { afterEach, describe, expect, it, vi } from "vitest";
import { readNodeEnv } from "../src/utils/env.js";

describe("readNodeEnv", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
  });

  it("reads NODE_ENV from process.env", () => {
    vi.stubEnv("NODE_ENV", "production");
    expect(readNodeEnv()).toBe("production");
  });

  it("skips process.env when Deno has not granted env access", () => {
    vi.stubEnv("NODE_ENV", "production");
    const querySync = vi.fn(() => ({ state: "prompt" }));
    vi.stubGlobal("Deno", { permissions: { querySync } });
    expect(readNodeEnv()).toBeUndefined();
    expect(querySync).toHaveBeenCalledWith({
      name: "env",
      variable: "NODE_ENV",
    });
  });

  it("reads NODE_ENV when Deno has granted env access", () => {
    vi.stubEnv("NODE_ENV", "test");
    vi.stubGlobal("Deno", {
      permissions: { querySync: () => ({ state: "granted" }) },
    });
    expect(readNodeEnv()).toBe("test");
  });

  it("returns undefined when reading the environment throws", () => {
    vi.stubGlobal("Deno", {
      permissions: {
        querySync: () => {
          throw new Error("NotCapable");
        },
      },
    });
    expect(readNodeEnv()).toBeUndefined();
  });
});
