import { describe, expect, it } from "vitest";
import { MemoryDedupeStore, verifyMailgun } from "../src/index.js";
import { signWebhook } from "../src/testing.js";

describe("Mailgun Webhook Verifier", () => {
  // Vector: hex HMAC-SHA256 of `<timestamp><token>`, keyed with the signing key.
  const secret = "key-mailgun";
  const signature = {
    timestamp: "1700000000",
    token: "c9d2b3a1e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4",
    signature:
      "91d12cb73976cd6416dffaaf7fd99c80a90762ef35a120e29fae635d62e29aea",
  };
  const body = JSON.stringify({
    signature,
    "event-data": { event: "delivered", id: "evt_1", timestamp: 1700000000.1 },
  });
  const now = 1700000000;

  it("verifies a JSON webhook", async () => {
    const result = await verifyMailgun({ headers: {}, body }, secret, { now });
    expect(result.valid).toBe(true);
    expect(result.timestamp).toBe(now);
    expect(result.eventType).toBe("delivered");
    expect(result.event?.["event-data"].id).toBe("evt_1");
  });

  it("verifies a form post", async () => {
    const form = new URLSearchParams({
      ...signature,
      event: "opened",
      recipient: "a@example.com",
    }).toString();
    const result = await verifyMailgun(
      {
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: form,
      },
      secret,
      { now },
    );
    expect(result.valid).toBe(true);
    expect(result.eventType).toBe("opened");
  });

  it("rejects a wrong key, a changed token and an expired timestamp", async () => {
    expect(
      (await verifyMailgun({ headers: {}, body }, "other", { now })).code,
    ).toBe("INVALID_SIGNATURE");
    const changed = body.replace(signature.token, "a".repeat(50));
    expect(
      (await verifyMailgun({ headers: {}, body: changed }, secret, { now }))
        .code,
    ).toBe("INVALID_SIGNATURE");
    expect(
      (await verifyMailgun({ headers: {}, body }, secret, { now: now + 301 }))
        .code,
    ).toBe("EXPIRED_TIMESTAMP");
  });

  it("rejects a body without signature fields", async () => {
    for (const bad of ["not json", "{}", '{"signature":"x"}']) {
      const result = await verifyMailgun({ headers: {}, body: bad }, secret);
      expect(result.code).toBe("MISSING_HEADER");
    }
  });

  it("dedupes on the signature token", async () => {
    const dedupeStore = new MemoryDedupeStore();
    const first = await verifyMailgun({ headers: {}, body }, secret, {
      now,
      dedupeStore,
    });
    expect(first.dedupeKey).toContain(signature.token);
    const second = await verifyMailgun({ headers: {}, body }, secret, {
      now,
      dedupeStore,
    });
    expect(second.code).toBe("DUPLICATE_EVENT");
  });

  it("round-trips signWebhook for JSON and form bodies", async () => {
    const json = await signWebhook("mailgun", {
      secret,
      payload: { "event-data": { event: "clicked" } },
    });
    expect(JSON.parse(json.body).signature.token).toHaveLength(48);
    expect((await verifyMailgun(json, secret)).eventType).toBe("clicked");

    const form = await signWebhook("mailgun", {
      secret,
      form: { event: "failed" },
    });
    const result = await verifyMailgun(form, secret);
    expect(result.valid).toBe(true);
    expect(result.eventType).toBe("failed");

    await expect(
      signWebhook("mailgun", { secret, payload: "raw" }),
    ).rejects.toThrow(/object/);
  });
});
