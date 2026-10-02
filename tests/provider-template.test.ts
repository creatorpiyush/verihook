// Test template — copy to `tests/<name>.test.ts` together with
// `src/providers/_template.ts` (see CONTRIBUTING.md, "Add a provider").
import { beforeAll, describe, expect, it } from "vitest";
import { computeHmacSha256 } from "../src/core/crypto.js";
import { registerProvider, verifyWebhook } from "../src/index.js";
import { acmeVerifier } from "../src/providers/_template.js";
import { bytesToHex } from "../src/utils/encoding.js";

const secret = "acme_test_secret";
// Prefer a real payload and signature from the provider's docs or official SDK
// as a known-good test vector, in addition to signing your own.
const body = JSON.stringify({ id: "evt_1", event_name: "order.paid" });
const now = 1_700_000_000;

async function sign(timestamp = now, payload = body, key = secret) {
  const digest = await computeHmacSha256(key, `${timestamp}.${payload}`);
  return {
    "x-acme-signature": bytesToHex(digest),
    "x-acme-timestamp": String(timestamp),
  };
}

describe("Acme (provider template)", () => {
  beforeAll(() => {
    // Built-in providers are added to src/providers/index.ts instead.
    registerProvider(acmeVerifier);
  });

  it("accepts a valid signature and reads the event", async () => {
    const result = await verifyWebhook(
      "acme",
      { headers: await sign(), body },
      secret,
      { now },
    );
    expect(result.valid).toBe(true);
    expect(result.timestamp).toBe(now);
    expect(result.eventType).toBe("order.paid");
  });

  it("rejects a wrong secret", async () => {
    const result = await verifyWebhook(
      "acme",
      { headers: await sign(now, body, "other"), body },
      secret,
      { now },
    );
    expect(result.code).toBe("INVALID_SIGNATURE");
  });

  it("rejects a modified body", async () => {
    const result = await verifyWebhook(
      "acme",
      { headers: await sign(), body: body.replace("order.paid", "order.free") },
      secret,
      { now },
    );
    expect(result.code).toBe("INVALID_SIGNATURE");
  });

  it("rejects missing and malformed headers", async () => {
    const missing = await verifyWebhook("acme", { headers: {}, body }, secret);
    expect(missing.code).toBe("MISSING_HEADER");

    const headers = { ...(await sign()), "x-acme-timestamp": "soon" };
    const malformed = await verifyWebhook("acme", { headers, body }, secret);
    expect(malformed.code).toBe("MISSING_HEADER");
  });

  it("rejects expired timestamps unless tolerance is disabled", async () => {
    const req = { headers: await sign(now - 600), body };
    const expired = await verifyWebhook("acme", req, secret, { now });
    expect(expired.code).toBe("EXPIRED_TIMESTAMP");

    const allowed = await verifyWebhook("acme", req, secret, {
      now,
      tolerance: 0,
    });
    expect(allowed.valid).toBe(true);
  });
});
