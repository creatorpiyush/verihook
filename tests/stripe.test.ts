import { describe, expect, it } from "vitest";
import { computeHmacSha256 } from "../src/core/crypto.js";
import { verifyStripe, verifyWebhook } from "../src/index.js";
import { bytesToHex } from "../src/utils/encoding.js";

describe("Stripe Webhook Verifier", () => {
  const secret = "whsec_test_secret_12345";
  const body = JSON.stringify({
    id: "evt_123",
    type: "payment_intent.succeeded",
  });
  const timestamp = 1700000000;

  it("should successfully verify valid Stripe signature", async () => {
    const payloadToSign = `${timestamp}.${body}`;
    const hmac = await computeHmacSha256(secret, payloadToSign);
    const signature = bytesToHex(hmac);
    const header = `t=${timestamp},v1=${signature}`;

    const req = {
      headers: { "stripe-signature": header },
      body,
    };

    const result = await verifyStripe(req, secret, { now: timestamp + 10 });
    expect(result.valid).toBe(true);
    expect(result.provider).toBe("stripe");
    expect(result.timestamp).toBe(timestamp);
  });

  it("should verify Stripe signature header containing multiple v1 signatures (secret rolling)", async () => {
    const payloadToSign = `${timestamp}.${body}`;
    const hmac = await computeHmacSha256(secret, payloadToSign);
    const validSig = bytesToHex(hmac);
    const header = `t=${timestamp},v1=old_invalid_sig_123,v1=${validSig}`;

    const req = {
      headers: { "stripe-signature": header },
      body,
    };

    const result = await verifyStripe(req, secret, { now: timestamp });
    expect(result.valid).toBe(true);
  });

  it("should reject when signature header is missing", async () => {
    const req = { headers: {}, body };
    const result = await verifyWebhook("stripe", req, secret);
    expect(result.valid).toBe(false);
    expect(result.code).toBe("MISSING_HEADER");
    expect(result.reason).toContain('Missing "stripe-signature" header');
  });

  it("should reject when timestamp is missing or corrupted", async () => {
    const req = { headers: { "stripe-signature": "v1=abc" }, body };
    const result = await verifyStripe(req, secret);
    expect(result.valid).toBe(false);
    expect(result.code).toBe("MISSING_HEADER");
  });

  it("should reject invalid signature", async () => {
    const req = {
      headers: {
        "stripe-signature": `t=${timestamp},v1=invalid_hex_signature`,
      },
      body,
    };
    const result = await verifyStripe(req, secret, { now: timestamp });
    expect(result.valid).toBe(false);
    expect(result.code).toBe("INVALID_SIGNATURE");
    expect(result.reason).toBe("Signature mismatch");
  });

  it("should reject timestamp older than tolerance window with EXPIRED_TIMESTAMP code", async () => {
    const payloadToSign = `${timestamp}.${body}`;
    const hmac = await computeHmacSha256(secret, payloadToSign);
    const signature = bytesToHex(hmac);
    const header = `t=${timestamp},v1=${signature}`;

    const req = { headers: { "stripe-signature": header }, body };
    const result = await verifyStripe(req, secret, {
      now: timestamp + 500,
      tolerance: 300,
    });

    expect(result.valid).toBe(false);
    expect(result.code).toBe("EXPIRED_TIMESTAMP");
    expect(result.reason).toContain("Timestamp outside tolerance window");
  });
});
