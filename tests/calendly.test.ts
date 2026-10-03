import { describe, expect, it } from "vitest";
import { verifyCalendly } from "../src/index.js";
import { signWebhook } from "../src/testing.js";

describe("Calendly Webhook Verifier", () => {
  // Vector: hex HMAC-SHA256 of `<t>.<body>`, keyed with the signing key.
  const secret = "calendly_key";
  const body =
    '{"event":"invitee.created","created_at":"2023-11-14T22:13:20.000000Z","created_by":"https://api.calendly.com/users/AAA","payload":{"email":"a@example.com"}}';
  const digest =
    "d6e180d65490baad58eb05bee811735ef6e1d522baaa05b7ee56482716cf700d";
  const now = 1700000000;
  const req = (value: string) => ({
    headers: { "Calendly-Webhook-Signature": value },
    body,
  });

  it("verifies a known-good signature", async () => {
    const result = await verifyCalendly(req(`t=${now},v1=${digest}`), secret, {
      now,
    });
    expect(result.valid).toBe(true);
    expect(result.timestamp).toBe(now);
    expect(result.eventType).toBe("invitee.created");
    expect(result.event?.payload.email).toBe("a@example.com");
  });

  it("uses a 3-minute default tolerance", async () => {
    const value = `t=${now},v1=${digest}`;
    expect(
      (await verifyCalendly(req(value), secret, { now: now + 180 })).valid,
    ).toBe(true);
    expect(
      (await verifyCalendly(req(value), secret, { now: now + 181 })).code,
    ).toBe("EXPIRED_TIMESTAMP");
  });

  it("rejects a wrong key, a modified body and malformed headers", async () => {
    expect(
      (await verifyCalendly(req(`t=${now},v1=${digest}`), "other", { now }))
        .code,
    ).toBe("INVALID_SIGNATURE");
    expect(
      (
        await verifyCalendly(
          {
            headers: { "calendly-webhook-signature": `t=${now},v1=${digest}` },
            body: body.replace("a@", "b@"),
          },
          secret,
          { now },
        )
      ).code,
    ).toBe("INVALID_SIGNATURE");
    for (const value of [
      `v1=${digest}`,
      `t=${now}`,
      `t=soon,v1=${digest}`,
      "garbage",
    ]) {
      expect((await verifyCalendly(req(value), secret, { now })).code).toBe(
        "MISSING_HEADER",
      );
    }
    expect((await verifyCalendly({ headers: {}, body }, secret)).code).toBe(
      "MISSING_HEADER",
    );
  });

  it("round-trips signWebhook", async () => {
    const hook = await signWebhook("calendly", {
      secret,
      payload: { event: "invitee.canceled" },
    });
    expect((await verifyCalendly(hook, secret)).eventType).toBe(
      "invitee.canceled",
    );
  });
});
