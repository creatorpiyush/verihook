import { describe, expect, it } from "vitest";
import { verifyPostmark } from "../src/index.js";
import { signWebhook } from "../src/testing.js";

describe("Postmark Webhook Verifier", () => {
  const secret = "pm_user:pm_pass";
  const body = JSON.stringify({
    RecordType: "Delivery",
    MessageID: "883953f4-6105-42a2-a16a-77a8eac79483",
    Recipient: "john@example.com",
  });
  // base64("pm_user:pm_pass")
  const authorization = "Basic cG1fdXNlcjpwbV9wYXNz";

  it("accepts matching Basic auth credentials", async () => {
    const result = await verifyPostmark(
      { headers: { Authorization: authorization }, body },
      secret,
    );
    expect(result.valid).toBe(true);
    expect(result.eventType).toBe("Delivery");
    expect(result.event?.Recipient).toBe("john@example.com");
  });

  it("accepts a lowercase scheme", async () => {
    const result = await verifyPostmark(
      {
        headers: { authorization: authorization.replace("Basic", "basic") },
        body,
      },
      secret,
    );
    expect(result.valid).toBe(true);
  });

  it("rejects wrong credentials and other auth schemes", async () => {
    expect(
      (
        await verifyPostmark(
          { headers: { authorization }, body },
          "pm_user:other",
        )
      ).code,
    ).toBe("INVALID_SIGNATURE");
    expect(
      (
        await verifyPostmark(
          { headers: { authorization: "Bearer cG1fdXNlcjpwbV9wYXNz" }, body },
          secret,
        )
      ).code,
    ).toBe("MISSING_HEADER");
    expect((await verifyPostmark({ headers: {}, body }, secret)).code).toBe(
      "MISSING_HEADER",
    );
  });

  it("rejects a secret that is not username:password", async () => {
    const result = await verifyPostmark(
      { headers: { authorization }, body },
      "just-a-password",
    );
    expect(result.code).toBe("INVALID_SECRET");
  });

  it("round-trips signWebhook and explains a bad secret", async () => {
    const hook = await signWebhook("postmark", {
      secret,
      payload: { RecordType: "Open" },
    });
    expect(hook.headers.authorization).toBe(authorization);
    expect((await verifyPostmark(hook, secret)).valid).toBe(true);
    await expect(signWebhook("postmark", { secret: "nope" })).rejects.toThrow(
      /username:password/,
    );
  });
});
