import { describe, expect, it } from "vitest";
import {
  verifyDiscord,
  verifyLemonSqueezy,
  verifyLinear,
  verifyPaddle,
  verifyPagerDuty,
  verifyRazorpay,
  verifyShopify,
  verifySlack,
  verifySquare,
  verifyStripe,
  verifySvix,
  verifyTwilio,
  verifyWebhook,
  verifyWebflow,
  verifyWorkOS,
  verifyZoom,
} from "../src/index.js";

describe("Additional Provider Edge Case & Negative Path Tests", () => {
  const dummyReq = {
    headers: {},
    body: JSON.stringify({ test: true }),
  };

  it("should reject missing headers for Slack, Svix, Discord, Twilio, Webflow, WorkOS, Zoom", async () => {
    expect((await verifySlack(dummyReq, "sec")).valid).toBe(false);
    expect((await verifySvix(dummyReq, "sec")).valid).toBe(false);
    expect((await verifyDiscord(dummyReq, "sec")).valid).toBe(false);
    expect((await verifyTwilio(dummyReq, "sec")).valid).toBe(false);
    expect((await verifyWebflow(dummyReq, "sec")).valid).toBe(false);
    expect((await verifyWorkOS(dummyReq, "sec")).valid).toBe(false);
    expect((await verifyZoom(dummyReq, "sec")).valid).toBe(false);
  });

  it("should reject invalid signature strings for all providers", async () => {
    const invalidHeadersReq = {
      headers: {
        "x-slack-signature": "v0=invalid",
        "x-slack-request-timestamp": String(Math.floor(Date.now() / 1000)),
        "svix-signature": "v1,invalid",
        "svix-id": "msg_1",
        "svix-timestamp": String(Math.floor(Date.now() / 1000)),
        "x-signature-ed25519": "invalid_ed25519_hex",
        "x-signature-timestamp": String(Math.floor(Date.now() / 1000)),
        "paddle-signature": "ts=100;h=invalid",
        "x-webflow-signature": "sha256=invalid",
        "x-webflow-timestamp": String(Math.floor(Date.now() / 1000)),
        "workos-signature": "t=100,v1=invalid",
        "x-zm-signature": "v0=invalid",
        "x-zm-request-timestamp": String(Math.floor(Date.now() / 1000)),
        "x-shopify-hmac-sha256": "invalid_b64",
        "linear-signature": "invalid_hex",
        "x-razorpay-signature": "invalid_hex",
        "x-signature": "invalid_hex",
        "x-pagerduty-signature": "v1=invalid",
        "x-square-hmacsha256-signature": "invalid_b64",
      },
      body: '{"test":true}',
      url: "https://example.com/webhook",
    };

    expect((await verifySlack(invalidHeadersReq, "sec")).valid).toBe(false);
    expect((await verifySvix(invalidHeadersReq, "sec")).valid).toBe(false);
    expect((await verifyDiscord(invalidHeadersReq, "sec")).valid).toBe(false);
    expect((await verifyPaddle(invalidHeadersReq, "sec")).valid).toBe(false);
    expect((await verifyWebflow(invalidHeadersReq, "sec")).valid).toBe(false);
    expect((await verifyWorkOS(invalidHeadersReq, "sec")).valid).toBe(false);
    expect((await verifyZoom(invalidHeadersReq, "sec")).valid).toBe(false);
    expect((await verifyShopify(invalidHeadersReq, "sec")).valid).toBe(false);
    expect((await verifyLinear(invalidHeadersReq, "sec")).valid).toBe(false);
    expect((await verifyRazorpay(invalidHeadersReq, "sec")).valid).toBe(false);
    expect((await verifyLemonSqueezy(invalidHeadersReq, "sec")).valid).toBe(
      false,
    );
    expect((await verifyPagerDuty(invalidHeadersReq, "sec")).valid).toBe(false);
    expect((await verifySquare(invalidHeadersReq, "sec")).valid).toBe(false);
  });

  it("should reject expired timestamps for timestamp-protected providers", async () => {
    const expiredTime = Math.floor(Date.now() / 1000) - 1000;
    const req = {
      headers: {
        "stripe-signature": `t=${expiredTime},v1=dummy`,
        "x-slack-signature": "v0=dummy",
        "x-slack-request-timestamp": String(expiredTime),
        "svix-signature": "v1,dummy",
        "svix-id": "msg_1",
        "svix-timestamp": String(expiredTime),
        "x-zm-signature": "v0=dummy",
        "x-zm-request-timestamp": String(expiredTime),
      },
      body: "{}",
    };

    expect((await verifyStripe(req, "sec")).code).toBe("EXPIRED_TIMESTAMP");
    expect((await verifySlack(req, "sec")).code).toBe("EXPIRED_TIMESTAMP");
    expect((await verifySvix(req, "sec")).code).toBe("EXPIRED_TIMESTAMP");
    expect((await verifyZoom(req, "sec")).code).toBe("EXPIRED_TIMESTAMP");
  });

  it("should test generic verifier algorithm and encoding options", async () => {
    const req = {
      headers: { "x-custom-sig": "invalid_sig" },
      body: "{}",
    };

    const res1 = await verifyWebhook("generic", req, "sec", {
      headerName: "x-custom-sig",
      algorithm: "sha1",
      encoding: "base64",
    });
    expect(res1.valid).toBe(false);

    const res2 = await verifyWebhook("generic", req, "sec", {
      headerName: "x-custom-sig",
      algorithm: "sha512",
      encoding: "prefix-hex",
    });
    expect(res2.valid).toBe(false);
  });
});
