import { describe, expect, it } from "vitest";
import { verifyTypeform } from "../src/index.js";
import { signWebhook } from "../src/testing.js";

describe("Typeform Webhook Verifier", () => {
  // Vector: base64 HMAC-SHA256 of the raw body, prefixed with "sha256=".
  const secret = "typeform_secret";
  const body =
    '{"event_id":"01H","event_type":"form_response","form_response":{"form_id":"abc","token":"tok","submitted_at":"2023-11-14T22:13:20Z","answers":[]}}';
  const headers = {
    "Typeform-Signature": "sha256=tpceH674tX4nhoHSDRkfV4/WGakns3OkNWpJ7GGZMko=",
  };

  it("verifies a known-good signature", async () => {
    const result = await verifyTypeform({ headers, body }, secret);
    expect(result.valid).toBe(true);
    expect(result.eventType).toBe("form_response");
    expect(result.event?.form_response.form_id).toBe("abc");
  });

  it("rejects a wrong secret, a modified body and a missing header", async () => {
    expect((await verifyTypeform({ headers, body }, "other")).code).toBe(
      "INVALID_SIGNATURE",
    );
    expect(
      (
        await verifyTypeform(
          { headers, body: body.replace("abc", "xyz") },
          secret,
        )
      ).code,
    ).toBe("INVALID_SIGNATURE");
    expect((await verifyTypeform({ headers: {}, body }, secret)).code).toBe(
      "MISSING_HEADER",
    );
  });

  it("round-trips signWebhook", async () => {
    const hook = await signWebhook("typeform", {
      secret,
      payload: { event_id: "1" },
    });
    expect((await verifyTypeform(hook, secret)).valid).toBe(true);
  });
});
