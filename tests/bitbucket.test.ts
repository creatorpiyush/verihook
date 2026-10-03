import { describe, expect, it } from "vitest";
import { verifyBitbucket, verifyWebhook } from "../src/index.js";
import { signWebhook } from "../src/testing.js";

describe("Bitbucket Webhook Verifier", () => {
  // Vector: hex HMAC-SHA256 of the raw body.
  const secret = "bb_secret";
  const body =
    '{"actor":{"display_name":"Jane"},"repository":{"full_name":"team/repo"},"push":{"changes":[]}}';
  const headers = {
    "X-Hub-Signature":
      "sha256=da6881ca2b290bd9a15792002f13b9542a8bb6db5783df3f13d161c43f118d91",
    "X-Event-Key": "repo:push",
  };

  it("verifies a known-good signature", async () => {
    const result = await verifyBitbucket({ headers, body }, secret);
    expect(result.valid).toBe(true);
    expect(result.eventType).toBe("repo:push");
    expect(result.event?.repository?.full_name).toBe("team/repo");
  });

  it("rejects a wrong secret, a modified body and a missing header", async () => {
    expect((await verifyBitbucket({ headers, body }, "other")).code).toBe(
      "INVALID_SIGNATURE",
    );
    expect(
      (
        await verifyBitbucket(
          { headers, body: body.replace("Jane", "Eve") },
          secret,
        )
      ).code,
    ).toBe("INVALID_SIGNATURE");
    expect((await verifyBitbucket({ headers: {}, body }, secret)).code).toBe(
      "MISSING_HEADER",
    );
  });

  it("hints at Bitbucket when verified as another provider", async () => {
    const result = await verifyWebhook("stripe", { headers, body }, secret);
    expect(result.code).toBe("MISSING_HEADER");
    expect(result.hint).toContain("bitbucket");
  });

  it("round-trips signWebhook", async () => {
    const hook = await signWebhook("bitbucket", {
      secret,
      event: "pullrequest:created",
    });
    const result = await verifyBitbucket(hook, secret);
    expect(result.valid).toBe(true);
    expect(result.eventType).toBe("pullrequest:created");
  });
});
