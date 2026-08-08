import { describe, expect, it } from "vitest";
import { computeHmacSha256 } from "../src/core/crypto.js";
import { verifySvix, verifyWebhook } from "../src/index.js";
import { base64ToBytes, bytesToBase64 } from "../src/utils/encoding.js";

describe("Svix / Resend / Clerk Webhook Verifier", () => {
  const rawSecret = "dGVzdF9zZWNyZXRfa2V5X2Zvcl9zdml4XzEyMw==";
  const whsecSecret = `whsec_${rawSecret}`;
  const body = JSON.stringify({
    type: "user.created",
    data: { id: "usr_100" },
  });
  const msgId = "msg_2L87j15Ww9S1F2x";
  const timestamp = 1700000000;

  it("should verify valid Svix webhook with whsec_ prefix", async () => {
    const payloadToSign = `${msgId}.${timestamp}.${body}`;
    const keyBytes = base64ToBytes(rawSecret);
    const hmac = await computeHmacSha256(keyBytes, payloadToSign);
    const sigBase64 = bytesToBase64(hmac);
    const headerSig = `v1,${sigBase64}`;

    const req = {
      headers: {
        "svix-id": msgId,
        "svix-timestamp": String(timestamp),
        "svix-signature": headerSig,
      },
      body,
    };

    const result = await verifySvix(req, whsecSecret, { now: timestamp + 5 });
    expect(result.valid).toBe(true);
    expect(result.provider).toBe("svix");
  });

  it("should verify Svix webhook with raw base64 secret (no whsec_ prefix)", async () => {
    const payloadToSign = `${msgId}.${timestamp}.${body}`;
    const keyBytes = base64ToBytes(rawSecret);
    const hmac = await computeHmacSha256(keyBytes, payloadToSign);
    const sigBase64 = bytesToBase64(hmac);

    const req = {
      headers: {
        "svix-id": msgId,
        "svix-timestamp": String(timestamp),
        "svix-signature": `v1,${sigBase64}`,
      },
      body,
    };

    const result = await verifySvix(req, rawSecret, { now: timestamp });
    expect(result.valid).toBe(true);
  });

  it("should verify Svix webhook with multiple space-separated signatures", async () => {
    const payloadToSign = `${msgId}.${timestamp}.${body}`;
    const keyBytes = base64ToBytes(rawSecret);
    const hmac = await computeHmacSha256(keyBytes, payloadToSign);
    const sigBase64 = bytesToBase64(hmac);

    const req = {
      headers: {
        "svix-id": msgId,
        "svix-timestamp": String(timestamp),
        "svix-signature": `v1,old_invalid_sig v1,${sigBase64}`,
      },
      body,
    };

    const result = await verifySvix(req, whsecSecret, { now: timestamp });
    expect(result.valid).toBe(true);
  });

  it("should reject expired timestamp with EXPIRED_TIMESTAMP code", async () => {
    const req = {
      headers: {
        "svix-id": msgId,
        "svix-timestamp": String(timestamp),
        "svix-signature": "v1,abc",
      },
      body,
    };

    const result = await verifySvix(req, whsecSecret, {
      now: timestamp + 500,
      tolerance: 300,
    });
    expect(result.valid).toBe(false);
    expect(result.code).toBe("EXPIRED_TIMESTAMP");
  });

  it("should verify Resend and Clerk aliases", async () => {
    const payloadToSign = `${msgId}.${timestamp}.${body}`;
    const keyBytes = base64ToBytes(rawSecret);
    const hmac = await computeHmacSha256(keyBytes, payloadToSign);
    const sigBase64 = bytesToBase64(hmac);

    const req = {
      headers: {
        "svix-id": msgId,
        "svix-timestamp": String(timestamp),
        "svix-signature": `v1,${sigBase64}`,
      },
      body,
    };

    const resendResult = await verifyWebhook("resend", req, whsecSecret, {
      now: timestamp,
    });
    const clerkResult = await verifyWebhook("clerk", req, whsecSecret, {
      now: timestamp,
    });

    expect(resendResult.valid).toBe(true);
    expect(clerkResult.valid).toBe(true);
  });
});
