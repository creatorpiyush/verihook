import { afterEach, describe, expect, it, vi } from "vitest";
import {
  verifyWebhook,
  verifyWebhookOrThrow,
  WebhookVerificationError,
} from "../src/index.js";
import { warnHintOnce } from "../src/core/diagnostics.js";
import { signWebhook } from "../src/testing/sign.js";

const payload = { id: "evt_1", amount: 2000, nested: { ok: true } };

async function prettyStripe(secret = "whsec_test") {
  // Providers often send pretty-printed JSON; re-serializing it changes the bytes.
  const hook = await signWebhook("stripe", {
    secret,
    payload: JSON.stringify(payload, null, 2),
  });
  const headers = {
    ...hook.headers,
    "content-length": String(new TextEncoder().encode(hook.body).length),
  };
  return { hook, headers };
}

describe("verification hints", () => {
  it("detects a parsed and re-serialized body", async () => {
    const { headers } = await prettyStripe();
    const result = await verifyWebhook(
      "stripe",
      { headers, body: JSON.stringify(payload) },
      "whsec_test",
    );
    expect(result.code).toBe("INVALID_SIGNATURE");
    expect(result.hint).toMatch(/content-length is \d+: it was modified/);
  });

  it("detects a body stream that was already consumed", async () => {
    const { headers } = await prettyStripe();
    const result = await verifyWebhook(
      "stripe",
      { headers, body: "" },
      "whsec_test",
    );
    expect(result.hint).toMatch(/body is empty but content-length/);
  });

  it("ignores content-length for compressed bodies", async () => {
    const { headers } = await prettyStripe();
    const result = await verifyWebhook(
      "stripe",
      {
        headers: { ...headers, "content-encoding": "gzip" },
        body: JSON.stringify(payload),
      },
      "whsec_test",
    );
    expect(result.hint ?? "").not.toMatch(/content-length/);
  });

  it.each([
    ["sk_test_123", /Stripe API key/],
    ["not_a_whsec", /start with whsec_/],
    [" whsec_test", /whitespace/],
    ['"whsec_test"', /wrapped in quotes/],
  ])("flags the Stripe secret %j", async (secret, pattern) => {
    const hook = await signWebhook("stripe", { secret: "whsec_right" });
    const result = await verifyWebhook(
      "stripe",
      { headers: hook.headers, body: hook.body },
      secret,
    );
    expect(result.hint).toMatch(pattern);
  });

  it("flags non-whsec secrets for Svix-based providers", async () => {
    const hook = await signWebhook("clerk", {
      secret: "whsec_dGVzdF9zZWNyZXQ=",
    });
    const result = await verifyWebhook(
      "clerk",
      { headers: hook.headers, body: hook.body },
      "c2VjcmV0",
    );
    expect(result.hint).toMatch(/Svix-based/);
  });

  it("points at the signed URL for Twilio and Square", async () => {
    const hook = await signWebhook("square", {
      secret: "sq",
      url: "https://public.example.com/hooks",
    });
    const result = await verifyWebhook(
      "square",
      { headers: hook.headers, body: hook.body, url: "http://internal/hooks" },
      "sq",
    );
    expect(result.hint).toMatch(/checked against http:\/\/internal\/hooks/);
  });

  it("names the provider whose headers were received", async () => {
    const hook = await signWebhook("github", { secret: "gh" });
    const result = await verifyWebhook(
      "stripe",
      { headers: hook.headers, body: hook.body },
      "whsec_x",
    );
    expect(result.code).toBe("MISSING_HEADER");
    expect(result.hint).toMatch(/"x-github-event" header, which github sends/);
  });

  it("notices when no headers were passed", async () => {
    const result = await verifyWebhook("github", { body: "{}" }, "gh");
    expect(result.hint).toMatch(/No request headers were passed/);
  });

  it("suggests options.now for replayed requests", async () => {
    const hook = await signWebhook("slack", {
      secret: "s",
      timestamp: 1_600_000_000,
    });
    const result = await verifyWebhook(
      "slack",
      { headers: hook.headers, body: hook.body },
      "s",
    );
    expect(result.code).toBe("EXPIRED_TIMESTAMP");
    expect(result.hint).toMatch(/options\.now/);
  });

  it("gives no hint on success or for a plain wrong secret", async () => {
    const hook = await signWebhook("github", { secret: "gh" });
    const ok = await verifyWebhook(
      "github",
      { headers: hook.headers, body: hook.body },
      "gh",
    );
    expect(ok.hint).toBeUndefined();
    const bad = await verifyWebhook(
      "github",
      { headers: hook.headers, body: hook.body },
      "other",
    );
    expect(bad.code).toBe("INVALID_SIGNATURE");
    expect(bad.hint).toBeUndefined();
  });

  it("carries the hint on errors and telemetry events", async () => {
    const hook = await signWebhook("stripe", { secret: "whsec_right" });
    const onVerify = vi.fn();
    await verifyWebhook(
      "stripe",
      { headers: hook.headers, body: hook.body },
      "sk_live_x",
      { onVerify },
    );
    expect(onVerify.mock.calls[0][0].hint).toMatch(/Stripe API key/);

    const err = await verifyWebhookOrThrow(
      "stripe",
      { headers: hook.headers, body: hook.body },
      "sk_live_x",
    ).catch((e) => e);
    expect(err).toBeInstanceOf(WebhookVerificationError);
    expect(err.hint).toMatch(/Stripe API key/);
  });
});

describe("warnHintOnce", () => {
  const originalEnv = process.env.NODE_ENV;
  afterEach(() => {
    process.env.NODE_ENV = originalEnv;
    vi.restoreAllMocks();
  });

  it("warns once per hint in development and stays quiet in production/test", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    process.env.NODE_ENV = "production";
    warnHintOnce("stripe", "hint-a");
    process.env.NODE_ENV = "test";
    warnHintOnce("stripe", "hint-a");
    expect(warn).not.toHaveBeenCalled();

    process.env.NODE_ENV = "development";
    warnHintOnce("stripe", "hint-a");
    warnHintOnce("stripe", "hint-a");
    warnHintOnce("stripe", "hint-b");
    expect(warn).toHaveBeenCalledTimes(2);
    expect(warn.mock.calls[0][0]).toBe(
      "[verihook] stripe verification hint: hint-a",
    );
  });
});
