import { describe, expect, it } from "vitest";
import {
  verifyDiscord,
  verifyGitHub,
  verifyMetaChallenge,
  verifyPaddle,
  verifySlack,
  verifySquare,
  verifyStripe,
  verifySvix,
  verifyWorkOS,
  verifyZoom,
} from "../src/index.js";

describe("Deep Provider Edge Cases for >95% Coverage", () => {
  const bodyStr = JSON.stringify({ test: true });

  it("should test Discord missing timestamp and invalid timestamp format", async () => {
    const noTsRes = await verifyDiscord(
      { headers: { "x-signature-ed25519": "sig" }, body: bodyStr },
      "sec",
    );
    expect(noTsRes.code).toBe("MISSING_HEADER");

    const invalidTsRes = await verifyDiscord(
      {
        headers: {
          "x-signature-ed25519": "sig",
          "x-signature-timestamp": "abc",
        },
        body: bodyStr,
      },
      "sec",
    );
    expect(invalidTsRes.code).toBe("MISSING_HEADER");
  });

  it("should test Zoom missing timestamp and invalid timestamp format", async () => {
    const noTsRes = await verifyZoom(
      { headers: { "x-zm-signature": "sig" }, body: bodyStr },
      "sec",
    );
    expect(noTsRes.code).toBe("MISSING_HEADER");

    const invalidTsRes = await verifyZoom(
      {
        headers: { "x-zm-signature": "sig", "x-zm-request-timestamp": "abc" },
        body: bodyStr,
      },
      "sec",
    );
    expect(invalidTsRes.code).toBe("MISSING_HEADER");
  });

  it("should test WorkOS invalid timestamp format, expired timestamp, and signature mismatch", async () => {
    const invalidTsRes = await verifyWorkOS(
      { headers: { "workos-signature": "t=abc,v1=hex" }, body: bodyStr },
      "sec",
    );
    expect(invalidTsRes.code).toBe("MISSING_HEADER");

    const expiredTs = Math.floor(Date.now() / 1000) - 1000;
    const expiredRes = await verifyWorkOS(
      {
        headers: { "workos-signature": `t=${expiredTs},v1=hex` },
        body: bodyStr,
      },
      "sec",
    );
    expect(expiredRes.code).toBe("EXPIRED_TIMESTAMP");

    const now = Math.floor(Date.now() / 1000);
    const mismatchRes = await verifyWorkOS(
      { headers: { "workos-signature": `t=${now},v1=badhex` }, body: bodyStr },
      "sec",
    );
    expect(mismatchRes.code).toBe("INVALID_SIGNATURE");
  });

  it("should test Square missing URL error path", async () => {
    const noUrlRes = await verifySquare(
      { headers: { "x-square-hmacsha256-signature": "sig" }, body: bodyStr },
      "sec",
    );
    expect(noUrlRes.code).toBe("MISSING_URL");
  });

  it("should test MetaChallenge URL string parameters", () => {
    const res = verifyMetaChallenge(
      "http://localhost/webhook?hub.mode=subscribe&hub.challenge=c123&hub.verify_token=my_secret",
      "my_secret",
    );
    expect(res.valid).toBe(true);
    expect(res.challenge).toBe("c123");
  });

  it("should test Stripe invalid timestamp format and missing v1 signature", async () => {
    const badTsRes = await verifyStripe(
      { headers: { "stripe-signature": "t=abc" }, body: bodyStr },
      "sec",
    );
    expect(badTsRes.code).toBe("MISSING_HEADER");

    const noV1Res = await verifyStripe(
      { headers: { "stripe-signature": "t=1700000000" }, body: bodyStr },
      "sec",
    );
    expect(noV1Res.code).toBe("MISSING_HEADER");
  });

  it("should test Slack missing timestamp or invalid timestamp format", async () => {
    const noTsRes = await verifySlack(
      { headers: { "x-slack-signature": "v0=sig" }, body: bodyStr },
      "sec",
    );
    expect(noTsRes.code).toBe("MISSING_HEADER");

    const badTsRes = await verifySlack(
      {
        headers: {
          "x-slack-signature": "v0=sig",
          "x-slack-request-timestamp": "abc",
        },
        body: bodyStr,
      },
      "sec",
    );
    expect(badTsRes.code).toBe("MISSING_HEADER");
  });

  it("should test Svix missing timestamp or ID", async () => {
    const noTsRes = await verifySvix(
      {
        headers: { "svix-signature": "v1,sig", "svix-id": "msg_1" },
        body: bodyStr,
      },
      "whsec_dGVzdF9zZWNyZXRfa2V5X2Zvcl9zdml4XzEyMw==",
    );
    expect(noTsRes.code).toBe("MISSING_HEADER");

    const noIdRes = await verifySvix(
      {
        headers: { "svix-signature": "v1,sig", "svix-timestamp": "1700000000" },
        body: bodyStr,
      },
      "whsec_dGVzdF9zZWNyZXRfa2V5X2Zvcl9zdml4XzEyMw==",
    );
    expect(noIdRes.code).toBe("MISSING_HEADER");
  });
});
