/**
 * Property-based fuzz tests (fast-check). They feed random headers, bodies, secrets
 * and payloads into the verifiers and check invariants that must hold for any input.
 */
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import {
  WebhookErrorCode,
  base64ToBytes,
  bytesToBase64,
  bytesToHex,
  hexToBytes,
  providers,
  timingSafeEqual,
  verifyWebhook,
} from "../src/index.js";
import { ecdsaDerToRaw, ecdsaRawToDer } from "../src/core/crypto.js";
import { SIGNABLE_PROVIDERS, signWebhook } from "../src/testing/sign.js";

const KNOWN_CODES = new Set<string>(Object.values(WebhookErrorCode));

// Providers that need no network (PayPal fetches certificates) and verify with a plain secret.
const OFFLINE_PROVIDERS = Object.keys(providers).filter(
  (name) => name !== "paypal",
);

const svixSecret = "whsec_dGVzdF9zZWNyZXRfa2V5X2Zvcl9zdml4XzEyMw==";

function secretFor(provider: string): string | undefined {
  if (["svix", "resend", "clerk"].includes(provider)) return svixSecret;
  if (provider === "phonepe") return "phonepe_user:phonepe_pass";
  if (provider === "postmark") return "postmark_user:postmark_pass";
  if (provider === "adyen") return "0123456789abcdef0123456789abcdef";
  if (provider === "discord" || provider === "sendgrid") return undefined;
  return `${provider}_fuzz_secret`;
}

const headerName = fc.oneof(
  fc.constantFrom(
    "stripe-signature",
    "x-hub-signature-256",
    "x-hub-signature",
    "svix-id",
    "svix-timestamp",
    "svix-signature",
    "webhook-signature",
    "x-slack-signature",
    "x-slack-request-timestamp",
    "x-twilio-signature",
    "x-signature-ed25519",
    "x-signature-timestamp",
    "authorization",
    "content-type",
  ),
  fc.string({ minLength: 1, maxLength: 24 }),
);
const headers = fc.dictionary(headerName, fc.string({ maxLength: 120 }), {
  maxKeys: 6,
});
const body = fc.oneof(fc.string({ maxLength: 300 }), fc.json());

describe("fuzz: verifyWebhook with random input", () => {
  it("never throws, never accepts and only returns known error codes", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.constantFrom(...OFFLINE_PROVIDERS),
        headers,
        body,
        fc.string({ maxLength: 40 }),
        async (provider, randomHeaders, randomBody, secret) => {
          const result = await verifyWebhook(
            provider as never,
            {
              headers: randomHeaders,
              body: randomBody,
              url: "https://example.com/hook",
            },
            secret,
            { tolerance: 0 },
          );
          expect(result.valid).toBe(false);
          expect(KNOWN_CODES.has(result.code as string)).toBe(true);
          expect(result.event).toBeUndefined();
        },
      ),
      { numRuns: 300 },
    );
  });
});

describe("fuzz: signed webhooks", () => {
  const signable = [...SIGNABLE_PROVIDERS].filter((p) => p !== "generic");

  it("accept any JSON payload signed by verihook/testing", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.constantFrom(...signable),
        fc.jsonValue(),
        async (provider, value) => {
          const payload = { id: "evt_fuzz", type: "fuzz.test", value };
          const hook = await signWebhook(provider, {
            secret: secretFor(provider),
            payload,
          });
          const result = await verifyWebhook(
            provider as never,
            { headers: hook.headers, body: hook.body, url: hook.url },
            hook.secret,
          );
          expect(result.valid, `${provider}: ${result.reason}`).toBe(true);
        },
      ),
      { numRuns: 200 },
    );
  });

  it.each(["stripe", "github", "svix", "slack", "shopify", "linear"])(
    "%s rejects any change to a signed body",
    async (provider) => {
      await fc.assert(
        fc.asyncProperty(
          fc.string({ minLength: 1, maxLength: 200 }),
          fc.nat(),
          fc.string({ minLength: 1, maxLength: 4 }),
          async (text, position, insert) => {
            const hook = await signWebhook(provider, {
              secret: secretFor(provider),
              payload: text,
            });
            const at = position % (hook.body.length + 1);
            const tampered =
              hook.body.slice(0, at) + insert + hook.body.slice(at);
            const result = await verifyWebhook(
              provider as never,
              { headers: hook.headers, body: tampered, url: hook.url },
              hook.secret,
            );
            expect(result.valid).toBe(false);
          },
        ),
        { numRuns: 100 },
      );
    },
  );

  it("rejects a different secret", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.constantFrom("stripe", "github", "slack", "shopify", "twilio"),
        fc.string({ minLength: 1, maxLength: 40 }),
        async (provider, other) => {
          const secret = secretFor(provider)!;
          fc.pre(other !== secret);
          const hook = await signWebhook(provider, {
            secret,
            payload: { id: "evt_fuzz" },
          });
          const result = await verifyWebhook(
            provider as never,
            { headers: hook.headers, body: hook.body, url: hook.url },
            other,
          );
          expect(result.valid).toBe(false);
        },
      ),
      { numRuns: 150 },
    );
  });
});

describe("fuzz: crypto and encoding helpers", () => {
  it("timingSafeEqual matches strict equality for strings", () => {
    fc.assert(
      fc.property(fc.string(), fc.string(), (a, b) => {
        expect(timingSafeEqual(a, b)).toBe(a === b);
        expect(timingSafeEqual(a, a)).toBe(true);
      }),
    );
  });

  it("timingSafeEqual matches byte equality for Uint8Arrays", () => {
    fc.assert(
      fc.property(fc.uint8Array(), fc.uint8Array(), (a, b) => {
        const equal =
          a.length === b.length && a.every((byte, i) => byte === b[i]);
        expect(timingSafeEqual(a, b)).toBe(equal);
      }),
    );
  });

  it("hex and base64 round-trip any non-empty bytes", () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 1, maxLength: 512 }), (bytes) => {
        expect(hexToBytes(bytesToHex(bytes))).toEqual(bytes);
        expect(base64ToBytes(bytesToBase64(bytes))).toEqual(bytes);
      }),
    );
    // Empty base64 is rejected on purpose: callers decode signatures, keys and
    // secrets, where an empty value must fail (e.g. a bare "whsec_" secret).
    expect(() => base64ToBytes("")).toThrow("Invalid base64 string");
  });

  it("hexToBytes rejects or decodes any string without crashing", () => {
    fc.assert(
      fc.property(fc.string(), (text) => {
        try {
          const bytes = hexToBytes(text);
          expect(bytesToHex(bytes)).toBe(
            text.replace(/^0x/i, "").toLowerCase(),
          );
        } catch (err) {
          expect((err as Error).message).toMatch(/hex/i);
        }
      }),
    );
  });

  it("ECDSA raw and DER signatures convert back and forth", () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 64, maxLength: 64 }), (raw) => {
        expect(ecdsaDerToRaw(ecdsaRawToDer(raw))).toEqual(raw);
      }),
    );
  });
});
