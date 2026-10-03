import { describe, expect, it } from "vitest";
import { verifyRecurly } from "../src/index.js";
import { signWebhook } from "../src/testing.js";

describe("Recurly Webhook Verifier", () => {
  // Vector: hex HMAC-SHA256 of `<ms timestamp>.<body>`, as Recurly's client
  // libraries (Recurly::Webhooks.verify_signature) compute it.
  const secret = "recurly_secret";
  const timestampMs = "1659641851000";
  const body =
    '{"id":"jx4s2ybfvmh8","object_type":"subscription","site_id":"site1","event_type":"created","event_time":"2022-08-04T19:37:31Z","account_code":"acct1"}';
  const digest =
    "ced656db6ac83dfaf36c31833b27f95b8e6b8eb1ebb7df69ba8f65821f1af98c";
  const now = 1659641851;
  const header = (value: string) => ({
    headers: { "recurly-signature": value },
    body,
  });

  it("verifies a known-good signature", async () => {
    const result = await verifyRecurly(
      header(`${timestampMs},${digest}`),
      secret,
      {
        now,
      },
    );
    expect(result.valid).toBe(true);
    expect(result.timestamp).toBe(now);
    expect(result.eventType).toBe("subscription.created");
    expect(result.event?.account_code).toBe("acct1");
  });

  it("accepts any signature during key rotation", async () => {
    const result = await verifyRecurly(
      header(`${timestampMs},${"a".repeat(64)},${digest}`),
      secret,
      { now },
    );
    expect(result.valid).toBe(true);
  });

  it("rejects a wrong secret and a modified body", async () => {
    const value = `${timestampMs},${digest}`;
    expect((await verifyRecurly(header(value), "other", { now })).code).toBe(
      "INVALID_SIGNATURE",
    );
    const modified = {
      headers: { "recurly-signature": value },
      body: body.replace("acct1", "acct2"),
    };
    expect((await verifyRecurly(modified, secret, { now })).code).toBe(
      "INVALID_SIGNATURE",
    );
  });

  it("rejects missing and malformed headers", async () => {
    expect((await verifyRecurly({ headers: {}, body }, secret)).code).toBe(
      "MISSING_HEADER",
    );
    for (const value of [timestampMs, `soon,${digest}`, `,${digest}`]) {
      expect((await verifyRecurly(header(value), secret, { now })).code).toBe(
        "MISSING_HEADER",
      );
    }
  });

  it("rejects an expired timestamp", async () => {
    const result = await verifyRecurly(
      header(`${timestampMs},${digest}`),
      secret,
      {
        now: now + 301,
      },
    );
    expect(result.code).toBe("EXPIRED_TIMESTAMP");
  });

  it("round-trips signWebhook", async () => {
    const hook = await signWebhook("recurly", {
      secret,
      payload: { object_type: "account", event_type: "updated" },
      timestamp: now,
    });
    expect(hook.headers["recurly-signature"]).toMatch(/^1659641851000,/);
    const result = await verifyRecurly(hook, secret, { now });
    expect(result.valid).toBe(true);
    expect(result.eventType).toBe("account.updated");
  });
});
