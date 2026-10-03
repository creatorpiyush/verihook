import { describe, expect, it } from "vitest";
import { verifySentry } from "../src/index.js";
import { signWebhook } from "../src/testing.js";

describe("Sentry Webhook Verifier", () => {
  // Vector: hex HMAC-SHA256 of the raw body, keyed with the client secret.
  const secret = "sentry_secret";
  const body =
    '{"action":"created","installation":{"uuid":"inst-1"},"data":{"issue":{"id":"1"}},"actor":{"type":"application"}}';
  const headers = {
    "Sentry-Hook-Signature":
      "c331a1851ad9016b22f6a22ce39c90df652bbe21a36a7c46664b09a4b1cbdbe6",
    "Sentry-Hook-Resource": "issue",
  };

  it("verifies a known-good signature", async () => {
    const result = await verifySentry({ headers, body }, secret);
    expect(result.valid).toBe(true);
    expect(result.eventType).toBe("issue.created");
    expect(result.event?.installation.uuid).toBe("inst-1");
  });

  it("falls back to the resource or action alone", async () => {
    const { "Sentry-Hook-Resource": _, ...noResource } = headers;
    expect(
      (await verifySentry({ headers: noResource, body }, secret)).eventType,
    ).toBe("created");
  });

  it("rejects a wrong secret, a modified body and a missing header", async () => {
    expect((await verifySentry({ headers, body }, "other")).code).toBe(
      "INVALID_SIGNATURE",
    );
    expect(
      (
        await verifySentry(
          { headers, body: body.replace("inst-1", "x") },
          secret,
        )
      ).code,
    ).toBe("INVALID_SIGNATURE");
    expect((await verifySentry({ headers: {}, body }, secret)).code).toBe(
      "MISSING_HEADER",
    );
  });

  it("round-trips signWebhook", async () => {
    const hook = await signWebhook("sentry", {
      secret,
      event: "error",
      payload: { action: "created" },
    });
    const result = await verifySentry(hook, secret);
    expect(result.valid).toBe(true);
    expect(result.eventType).toBe("error.created");
  });
});
