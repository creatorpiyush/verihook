import { describe, expect, it } from "vitest";
import { verifyIntercom, verifyWebhook } from "../src/index.js";
import { signWebhook } from "../src/testing.js";

describe("Intercom Webhook Verifier", () => {
  // Vector: hex HMAC-SHA1 of the raw body, keyed with the client secret.
  const secret = "intercom_secret";
  const body =
    '{"type":"notification_event","id":"notif_1","topic":"conversation.user.created","app_id":"abc","created_at":1700000000,"data":{"type":"notification_event_data","item":{"type":"conversation","id":"1"}}}';
  const headers = {
    "X-Hub-Signature": "sha1=e0d6deaa5785a871c44a56b6c3138ce190b6cc98",
  };

  it("verifies a known-good signature", async () => {
    const result = await verifyIntercom({ headers, body }, secret);
    expect(result.valid).toBe(true);
    expect(result.eventType).toBe("conversation.user.created");
    expect(result.event?.data.item.id).toBe("1");
  });

  it("rejects a wrong secret, a modified body and a missing header", async () => {
    expect((await verifyIntercom({ headers, body }, "other")).code).toBe(
      "INVALID_SIGNATURE",
    );
    expect(
      (
        await verifyIntercom(
          { headers, body: body.replace("abc", "xyz") },
          secret,
        )
      ).code,
    ).toBe("INVALID_SIGNATURE");
    expect((await verifyIntercom({ headers: {}, body }, secret)).code).toBe(
      "MISSING_HEADER",
    );
  });

  it("hints at Intercom when verified as another provider", async () => {
    const result = await verifyWebhook("stripe", { headers, body }, secret);
    expect(result.hint).toContain("intercom");
  });

  it("round-trips signWebhook", async () => {
    const hook = await signWebhook("intercom", {
      secret,
      payload: { topic: "ping" },
    });
    expect(hook.headers["x-hub-signature"]).toMatch(/^sha1=[0-9a-f]{40}$/);
    expect((await verifyIntercom(hook, secret)).eventType).toBe("ping");
  });
});
