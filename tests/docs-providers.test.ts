/**
 * Keeps the docs site's provider data (docs/src/data/providers.mjs) in line with
 * the code: identifiers, import paths and the testing snippet on each page.
 */
import { describe, expect, it } from "vitest";
import { providers as builtIn } from "../src/index.js";
import { signWebhook } from "../src/testing/sign.js";
import { providers as pages } from "../docs/src/data/providers.mjs";

describe("docs provider pages", () => {
  it("document every built-in provider", () => {
    const ids = new Set(pages.flatMap((p) => [p.id, ...(p.aliases ?? [])]));
    const missing = Object.keys(builtIn).filter(
      (name) => name !== "generic" && !ids.has(name),
    );
    expect(missing).toEqual([]);
  });

  it.each(pages.map((p) => [p.id, p] as const))(
    "%s: the import and testing snippet work",
    async (_id, page) => {
      const entry = (await import(`../src/entries/${page.entry}.ts`)) as Record<
        string,
        unknown
      >;
      const verify = entry[page.fn];
      expect(typeof verify, `${page.fn} in verihook/${page.entry}`).toBe(
        "function",
      );
      if (page.signable === false) return;

      const hook = await signWebhook(page.id, {
        secret: page.testSecret,
        payload: { id: "evt_test" },
      });
      const result = await (
        verify as (
          req: unknown,
          secret: string,
        ) => Promise<{ valid: boolean; reason?: string }>
      )({ headers: hook.headers, body: hook.body, url: hook.url }, hook.secret);
      expect(result.valid, result.reason).toBe(true);
    },
  );
});
