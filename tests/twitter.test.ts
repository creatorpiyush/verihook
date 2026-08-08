import { describe, expect, it } from "vitest";
import { computeHmacSha256 } from "../src/core/crypto.js";
import {
  verifyTwitter,
  verifyTwitterCrc,
  verifyWebhook,
} from "../src/index.js";
import { bytesToBase64 } from "../src/utils/encoding.js";

describe("Twitter / X API Webhook Verifier", () => {
  const secret = "twitter_consumer_secret_777";
  const body = JSON.stringify({
    for_user_id: "12345",
    tweet_create_events: [{ id: "99" }],
  });

  it("should verify valid Twitter / X signature", async () => {
    const hmac = await computeHmacSha256(secret, body);
    const signature = `sha256=${bytesToBase64(hmac)}`;

    const req = {
      headers: { "x-twitter-webhooks-signature": signature },
      body,
    };

    const result = await verifyTwitter(req, secret);
    expect(result.valid).toBe(true);
    expect(result.provider).toBe("twitter");
  });

  it("should reject invalid Twitter signature", async () => {
    const req = {
      headers: { "x-twitter-webhooks-signature": "sha256=invalid_b64==" },
      body,
    };
    const result = await verifyWebhook("twitter", req, secret);
    expect(result.valid).toBe(false);
    expect(result.code).toBe("INVALID_SIGNATURE");
  });

  it("should compute verifyTwitterCrc challenge response token", async () => {
    const crcToken = "challenge_token_abc123";
    const res = await verifyTwitterCrc(crcToken, secret);
    expect(res.response_token).toContain("sha256=");
  });
});
