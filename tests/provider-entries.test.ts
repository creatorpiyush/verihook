import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import * as MainIndex from "../src/index.js";
import { providers } from "../src/providers/index.js";
import { SIGNABLE_PROVIDERS, signWebhook } from "../src/testing/sign.js";

const root = join(__dirname, "..");
const entryNames = readdirSync(join(root, "src/entries"))
  .filter((file) => file.endsWith(".ts"))
  .map((file) => file.slice(0, -3))
  .sort();
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));

const svixSecret = "whsec_dGVzdF9zZWNyZXRfa2V5X2Zvcl9zdml4XzEyMw==";

function secretFor(provider: string): string | undefined {
  if (["svix", "resend", "clerk"].includes(provider)) return svixSecret;
  if (provider === "phonepe") return "phonepe_user:phonepe_pass";
  if (provider === "postmark") return "postmark_user:postmark_pass";
  if (provider === "adyen") return "0123456789abcdef0123456789abcdef";
  if (provider === "discord" || provider === "sendgrid") return undefined;
  return `${provider}_test_secret`;
}

type VerifyFn = (
  req: MainIndex.WebhookRequestInput,
  secret: string,
  opts?: MainIndex.VerifyWebhookOptions,
) => Promise<MainIndex.VerificationResult>;

async function loadEntry(name: string): Promise<Record<string, unknown>> {
  return import(`../src/entries/${name}.ts`);
}

/** The bound verify functions of an entry, keyed by provider name (`verifyGitLab` -> "gitlab"). */
function boundVerifiers(entry: Record<string, unknown>): [string, VerifyFn][] {
  return Object.entries(entry)
    .filter(
      ([key, value]) =>
        typeof value === "function" &&
        /^verify[A-Z]/.test(key) &&
        !/(Crc|Challenge)$/.test(key),
    )
    .map(([key, value]) => [
      key.slice("verify".length).toLowerCase(),
      value as VerifyFn,
    ]);
}

describe("per-provider entry points", () => {
  it("has one entry per built-in provider verifier", () => {
    const verifierFiles = new Set(
      Object.values(providers)
        .map((verifier) => verifier.name)
        .filter((name) => name !== "generic"),
    );
    for (const name of verifierFiles) {
      expect(entryNames, `missing src/entries for ${name}`).toContain(name);
    }
  });

  it("exposes every entry as a package subpath export", () => {
    for (const name of entryNames) {
      expect(pkg.exports[`./${name}`]).toEqual({
        types: `./dist/${name}.d.ts`,
        import: `./dist/${name}.mjs`,
        require: `./dist/${name}.js`,
      });
    }
  });

  it("marks the package as free of side effects", () => {
    expect(pkg.sideEffects).toBe(false);
  });

  it.each(entryNames)(
    "verihook/%s exports the same API names as the main entry",
    async (name) => {
      const entry = await loadEntry(name);
      expect(entry[`${name}Verifier`]).toBe(providers[name]);
      expect(entry.WebhookErrorCode).toBe(MainIndex.WebhookErrorCode);
      // `<name>Verifier` is reachable from the main entry through `providers`.
      for (const key of Object.keys(entry)) {
        if (key === `${name}Verifier`) continue;
        expect(MainIndex, `verihook/${name} exports ${key}`).toHaveProperty(
          key,
        );
      }
    },
  );

  it.each(entryNames)(
    "verihook/%s verifies signed webhooks like verifyWebhook",
    async (name) => {
      const entry = await loadEntry(name);
      const bound = boundVerifiers(entry);
      expect(bound.length).toBeGreaterThan(0);

      for (const [provider, verify] of bound) {
        if (!SIGNABLE_PROVIDERS.has(provider)) continue;
        const hook = await signWebhook(provider, {
          secret: secretFor(provider),
          payload: { id: "evt_entry", type: "test.event" },
        });
        const req = { headers: hook.headers, body: hook.body, url: hook.url };

        const result = await verify(req, hook.secret);
        expect(result.valid, `${name}: ${provider} ${result.reason}`).toBe(
          true,
        );
        expect(result.event).toEqual(
          (await MainIndex.verifyWebhook(provider as never, req, hook.secret))
            .event,
        );
      }
    },
  );

  it("runs the shared pipeline: secret checks, hints and dedupe", async () => {
    const { verifyStripe } = await import("../src/entries/stripe.js");
    const hook = await signWebhook("stripe", {
      secret: "whsec_entry",
      payload: { id: "evt_dupe", type: "invoice.paid" },
    });
    const req = { headers: hook.headers, body: hook.body };

    const missing = await verifyStripe(req, "");
    expect(missing.code).toBe(MainIndex.WebhookErrorCode.INVALID_SECRET);

    const wrong = await verifyStripe(
      { headers: { "x-hub-signature-256": "sha256=00" }, body: hook.body },
      "whsec_entry",
    );
    expect(wrong.code).toBe(MainIndex.WebhookErrorCode.MISSING_HEADER);
    expect(wrong.hint).toMatch(/github/i);

    const dedupeStore = new MainIndex.MemoryDedupeStore();
    const first = await verifyStripe(req, "whsec_entry", { dedupeStore });
    expect(first.valid).toBe(true);
    expect(first.eventType).toBe("invoice.paid");
    expect(first.dedupeKey).toBe("stripe:evt_dupe");
    const second = await verifyStripe(req, "whsec_entry", { dedupeStore });
    expect(second.code).toBe(MainIndex.WebhookErrorCode.DUPLICATE_EVENT);
  });

  it("is not affected by registerProvider overrides", async () => {
    const { verifyLinear } = await import("../src/entries/linear.js");
    const original = providers.linear;
    MainIndex.registerProvider({
      name: "linear",
      verify: async () => ({ valid: true, provider: "linear" }),
    });
    try {
      const result = await verifyLinear({ headers: {}, body: "{}" }, "secret");
      expect(result.valid).toBe(false);
    } finally {
      providers.linear = original;
    }
  });
});
