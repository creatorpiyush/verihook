import { describe, expect, it } from "vitest";
import { verifyAuthorizeNet } from "../src/index.js";
import { signWebhook } from "../src/testing.js";

describe("Authorize.net Webhook Verifier", () => {
  // Vector: uppercase hex HMAC-SHA512 of the raw body, keyed with the Signature Key as-is.
  const secret = "ANET_SIG_KEY";
  const body =
    '{"notificationId":"d0e8e7fe-c3e7-4add-a480-27bc5ce28a14","eventType":"net.authorize.payment.authcapture.created","eventDate":"2017-03-29T20:48:02.0080095Z","webhookId":"63d6fea2-aa13-4b1d-a204-f5fbc15942b7","payload":{"responseCode":1,"authAmount":45.00,"entityName":"transaction","id":"60020981676"}}';
  const signature =
    "sha512=3D61DDAD54AB05A8932039B6C4D7A934DF9219708C93C211BCC69EA0E257EDD075BA181061AD4CD8031C5CBD7B83BDE5E03D0A3F1026D0B7C61985E32BB1D94A";

  it("verifies a known-good signature", async () => {
    const result = await verifyAuthorizeNet(
      { headers: { "X-ANET-Signature": signature }, body },
      secret,
    );
    expect(result.valid).toBe(true);
    expect(result.eventType).toBe("net.authorize.payment.authcapture.created");
    expect(result.event?.webhookId).toBe(
      "63d6fea2-aa13-4b1d-a204-f5fbc15942b7",
    );
  });

  it("accepts a lowercase digest", async () => {
    const result = await verifyAuthorizeNet(
      { headers: { "x-anet-signature": signature.toLowerCase() }, body },
      secret,
    );
    expect(result.valid).toBe(true);
  });

  it("rejects a wrong key and a modified body", async () => {
    const headers = { "x-anet-signature": signature };
    expect((await verifyAuthorizeNet({ headers, body }, "other")).code).toBe(
      "INVALID_SIGNATURE",
    );
    expect(
      (
        await verifyAuthorizeNet(
          { headers, body: body.replace("45.00", "4500") },
          secret,
        )
      ).code,
    ).toBe("INVALID_SIGNATURE");
  });

  it("rejects a missing signature header", async () => {
    const result = await verifyAuthorizeNet({ headers: {}, body }, secret);
    expect(result.code).toBe("MISSING_HEADER");
  });

  it("uses notificationId as the dedupe key", async () => {
    const { MemoryDedupeStore } = await import("../src/index.js");
    const dedupeStore = new MemoryDedupeStore();
    const req = { headers: { "x-anet-signature": signature }, body };
    const first = await verifyAuthorizeNet(req, secret, { dedupeStore });
    expect(first.dedupeKey).toContain("d0e8e7fe-c3e7-4add-a480-27bc5ce28a14");
    const second = await verifyAuthorizeNet(req, secret, { dedupeStore });
    expect(second.code).toBe("DUPLICATE_EVENT");
  });

  it("round-trips signWebhook", async () => {
    const hook = await signWebhook("authorizenet", {
      secret,
      payload: { eventType: "x" },
    });
    expect(hook.headers["x-anet-signature"]).toMatch(/^sha512=[0-9A-F]{128}$/);
    expect((await verifyAuthorizeNet(hook, secret)).valid).toBe(true);
  });
});
