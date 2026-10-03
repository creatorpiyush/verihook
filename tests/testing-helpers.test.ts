import { describe, expect, it } from "vitest";
import { verifyWebhook } from "../src/index.js";
import {
  SIGNABLE_PROVIDERS,
  createSignedRequest,
  signWebhook,
} from "../src/testing/sign.js";

const svixSecret = "whsec_dGVzdF9zZWNyZXRfa2V5X2Zvcl9zdml4XzEyMw==";

function secretFor(provider: string): string {
  if (["svix", "resend", "clerk"].includes(provider)) return svixSecret;
  if (provider === "phonepe") return "phonepe_user:phonepe_pass";
  if (provider === "postmark") return "postmark_user:postmark_pass";
  if (provider === "adyen") return "0123456789abcdef0123456789abcdef";
  return `${provider}_test_secret`;
}

describe("signWebhook round-trips through verifyWebhook", () => {
  it.each([...SIGNABLE_PROVIDERS])("%s (JSON payload)", async (provider) => {
    const hook = await signWebhook(provider, {
      secret: provider === "discord" ? undefined : secretFor(provider),
      payload: { id: "evt_1", type: "test.event" },
    });
    const result = await verifyWebhook(
      provider,
      { headers: hook.headers, body: hook.body, url: hook.url },
      hook.secret,
    );
    expect(result.valid).toBe(true);
  });

  it.each(["slack", "twilio"])("%s (form payload)", async (provider) => {
    const hook = await signWebhook(provider, {
      secret: secretFor(provider),
      form: { Body: "Hello", From: "+15551234567", team_id: "T1" },
      url: "https://hooks.example.com/webhooks/form",
    });
    expect(hook.headers["content-type"]).toBe(
      "application/x-www-form-urlencoded",
    );
    const result = await verifyWebhook(
      provider,
      { headers: hook.headers, body: hook.body, url: hook.url },
      hook.secret,
    );
    expect(result.valid).toBe(true);
  });

  it("keeps string payloads byte-for-byte", async () => {
    const payload = '{\n  "id": "evt_pretty"\n}';
    const hook = await signWebhook("stripe", { secret: "whsec_x", payload });
    expect(hook.body).toBe(payload);
  });

  it("honours a fixed timestamp and webhook id", async () => {
    const hook = await signWebhook("svix", {
      secret: svixSecret,
      timestamp: 1700000000,
      webhookId: "msg_fixed",
    });
    expect(hook.headers["svix-id"]).toBe("msg_fixed");
    expect(hook.headers["svix-timestamp"]).toBe("1700000000");
    const result = await verifyWebhook(
      "svix",
      { headers: hook.headers, body: hook.body },
      svixSecret,
      { now: 1700000000 },
    );
    expect(result.valid).toBe(true);
  });

  it("signs generic webhooks with custom header, algorithm and encoding", async () => {
    const opts = {
      headerName: "X-Custom-Sig",
      algorithm: "sha512" as const,
      encoding: "prefix-hex" as const,
    };
    const hook = await signWebhook("generic", { secret: "s", ...opts });
    expect(hook.headers["x-custom-sig"]).toMatch(/^sha512=[0-9a-f]{128}$/);
    const result = await verifyWebhook(
      "generic",
      { headers: hook.headers, body: hook.body },
      "s",
      opts,
    );
    expect(result.valid).toBe(true);
  });

  it("derives a stable Discord public key from a private key seed", async () => {
    const privateKey = "11".repeat(32);
    const a = await signWebhook("discord", { privateKey });
    const b = await signWebhook("discord", { privateKey });
    expect(a.secret).toMatch(/^[0-9a-f]{64}$/);
    expect(a.secret).toBe(b.secret);
    const result = await verifyWebhook(
      "discord",
      { headers: a.headers, body: a.body },
      a.secret,
    );
    expect(result.valid).toBe(true);
  });

  it("merges extra headers", async () => {
    const hook = await signWebhook("shopify", {
      secret: "s",
      headers: { "x-shopify-topic": "orders/create" },
    });
    expect(hook.headers["x-shopify-topic"]).toBe("orders/create");
    expect(hook.headers["x-shopify-hmac-sha256"]).toBeTruthy();
  });

  it("returns a Fetch Request with createSignedRequest", async () => {
    const req = await createSignedRequest("github", {
      secret: "gh",
      payload: { zen: "Keep it logically awesome." },
      event: "ping",
    });
    expect(req.method).toBe("POST");
    expect(req.headers.get("x-github-event")).toBe("ping");
    const result = await verifyWebhook("github", req, "gh");
    expect(result.valid).toBe(true);
  });
});

describe("signWebhook errors", () => {
  it("requires a secret for HMAC providers", async () => {
    await expect(signWebhook("stripe")).rejects.toThrow(
      /requires options.secret/,
    );
  });

  it("refuses PayPal", async () => {
    await expect(signWebhook("paypal", { secret: "x" })).rejects.toThrow(
      /cannot be signed locally/,
    );
  });

  it("refuses unknown providers", async () => {
    await expect(
      signWebhook("my-custom-provider", { secret: "x" }),
    ).rejects.toThrow(/does not know how to sign/);
  });

  it("rejects a malformed Discord seed", async () => {
    await expect(
      signWebhook("discord", { privateKey: "abcd" }),
    ).rejects.toThrow(/32-byte/);
  });
});
