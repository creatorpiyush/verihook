import { describe, expect, it } from "vitest";
import { signWebhook } from "../src/testing.js";
import { createWebhookHandler } from "../src/next.js";
import { verifyStripe } from "../src/entries/stripe.js";
import { verifyWebhook, WebhookErrorCode } from "../src/index.js";

const NEW = "whsec_new_secret";
const OLD = "whsec_old_secret";
const payload = { id: "evt_rotate", type: "invoice.paid" };

async function signedBy(secret: string, opts?: { timestamp?: number }) {
  const { headers, body } = await signWebhook("stripe", {
    payload,
    secret,
    ...opts,
  });
  return { headers, body };
}

describe("secret rotation", () => {
  it("accepts a delivery signed with any secret in the list", async () => {
    for (const signer of [NEW, OLD]) {
      const result = await verifyWebhook("stripe", await signedBy(signer), [
        NEW,
        OLD,
      ]);
      expect(result.valid).toBe(true);
      expect(result.event).toEqual(payload);
    }
  });

  it("works through the per-provider entry points", async () => {
    expect((await verifyStripe(await signedBy(OLD), [NEW, OLD])).valid).toBe(
      true,
    );
  });

  it("reports the first secret's failure when none matches", async () => {
    const result = await verifyWebhook(
      "stripe",
      await signedBy("whsec_other"),
      [NEW, OLD],
    );
    expect(result.code).toBe(WebhookErrorCode.INVALID_SIGNATURE);
  });

  it("does not mask an expired timestamp", async () => {
    const stale = await signedBy(OLD, {
      timestamp: Math.floor(Date.now() / 1000) - 3600,
    });
    const result = await verifyWebhook("stripe", stale, [NEW, OLD]);
    expect(result.code).toBe(WebhookErrorCode.EXPIRED_TIMESTAMP);
  });

  it("rejects an empty list, or one with only empty secrets", async () => {
    for (const secrets of [[], [""]]) {
      const result = await verifyWebhook(
        "stripe",
        await signedBy(NEW),
        secrets,
      );
      expect(result.code).toBe(WebhookErrorCode.INVALID_SECRET);
    }
  });

  it("skips empty entries, e.g. an unset OLD secret env var", async () => {
    expect(
      (await verifyWebhook("stripe", await signedBy(NEW), ["", NEW])).valid,
    ).toBe(true);
  });

  it("adapters accept a resolver returning a list", async () => {
    const handler = createWebhookHandler(
      "stripe",
      async () => [NEW, OLD],
      () => undefined,
    );
    const { headers, body } = await signedBy(OLD);
    const res = await handler(
      new Request("https://example.com/webhooks/stripe", {
        method: "POST",
        headers,
        body,
      }),
    );
    expect(res.status).toBe(200);
  });
});
