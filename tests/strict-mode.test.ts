import crypto from "node:crypto";
import { describe, expect, it } from "vitest";
import { verifyWebhook, WebhookErrorCode } from "../src/index.js";
import { SIGNABLE_PROVIDERS, signWebhook } from "../src/testing/sign.js";

const secret = "strict_secret";
const body = JSON.stringify({ id: "evt_strict", type: "test.event" });
const now = Math.floor(Date.now() / 1000);
const hmac = (alg: string, data: string, key = secret) =>
  crypto.createHmac(alg, key).update(data).digest("hex");
const sha256 = (data: string) =>
  crypto.createHash("sha256").update(data).digest("hex");

// Each provider's weaker fallback scheme, signed correctly.
const fallbacks: [string, Record<string, string>][] = [
  ["github", { "x-hub-signature": `sha1=${hmac("sha1", body)}` }],
  ["meta", { "x-hub-signature": `sha1=${hmac("sha1", body)}` }],
  [
    "hubspot",
    {
      "x-hubspot-signature": sha256(secret + body),
      "x-hubspot-signature-version": "v1",
    },
  ],
  ["gitlab", { "x-gitlab-token": secret }],
  ["webflow", { "x-webflow-signature": hmac("sha256", body) }],
  ["linear", { "linear-signature": hmac("sha256", body) }],
  [
    "paddle",
    { "paddle-signature": `ts=${now};h=${hmac("sha256", `${now}:${body}`)}` },
  ],
];

describe("strict mode", () => {
  it.each(fallbacks)(
    "%s: the fallback verifies by default and fails with WEAK_SCHEME when strict",
    async (provider, headers) => {
      const req = { headers, body };
      const loose = await verifyWebhook(provider as never, req, secret);
      expect(loose.valid, loose.reason).toBe(true);

      const strict = await verifyWebhook(provider as never, req, secret, {
        strict: true,
      });
      expect(strict.code).toBe(WebhookErrorCode.WEAK_SCHEME);
      expect(strict.reason).toContain("options.strict");
    },
  );

  it("paddle: h1 still verifies in strict mode when a legacy h is also sent", async () => {
    const sig = hmac("sha256", `${now}:${body}`);
    const result = await verifyWebhook(
      "paddle",
      { headers: { "paddle-signature": `ts=${now};h=bad;h1=${sig}` }, body },
      secret,
      { strict: true },
    );
    expect(result.valid, result.reason).toBe(true);
  });

  it("every provider signed by verihook/testing verifies in strict mode", async () => {
    for (const provider of SIGNABLE_PROVIDERS) {
      if (provider === "generic") continue;
      const key = [
        "svix",
        "resend",
        "clerk",
        "gitlab",
        "standard-webhooks",
      ].includes(provider)
        ? "whsec_c3RyaWN0X3NlY3JldF9mb3JfdGVzdHM="
        : provider === "adyen"
          ? "0123456789abcdef0123456789abcdef"
          : ["phonepe", "postmark"].includes(provider)
            ? "user:pass"
            : secret;
      const hook = await signWebhook(provider, {
        secret: key,
        payload: {
          id: "evt_strict",
          type: "test.event",
          webhookTimestamp: now * 1000,
        },
      });
      const result = await verifyWebhook(
        provider as never,
        { headers: hook.headers, body: hook.body, url: hook.url },
        hook.secret,
        { ...hook.verifyOptions, strict: true },
      );
      expect(result.valid, `${provider}: ${result.reason}`).toBe(true);
    }
  });
});

describe("timestampVerified", () => {
  it("is true when a signed timestamp was checked", async () => {
    const hook = await signWebhook("stripe", {
      secret: "whsec_x",
      payload: { id: "evt" },
    });
    const result = await verifyWebhook("stripe", hook, "whsec_x");
    expect(result.timestampVerified).toBe(true);
  });

  it("is false for providers without a timestamp, and with tolerance: 0", async () => {
    const gh = await signWebhook("github", { secret, payload: { id: "evt" } });
    expect((await verifyWebhook("github", gh, secret)).timestampVerified).toBe(
      false,
    );

    const st = await signWebhook("stripe", {
      secret: "whsec_x",
      payload: { id: "evt" },
    });
    const off = await verifyWebhook("stripe", st, "whsec_x", { tolerance: 0 });
    expect(off).toMatchObject({ valid: true, timestampVerified: false });
  });

  it("is reported to telemetry", async () => {
    const hook = await signWebhook("stripe", {
      secret: "whsec_x",
      payload: { id: "evt" },
    });
    let seen: boolean | undefined;
    await verifyWebhook("stripe", hook, "whsec_x", {
      onVerify: (event) => {
        seen = event.timestampVerified;
      },
    });
    expect(seen).toBe(true);
  });
});
