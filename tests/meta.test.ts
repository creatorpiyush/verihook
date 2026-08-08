import { describe, expect, it } from "vitest";
import { computeHmacSha1, computeHmacSha256 } from "../src/core/crypto.js";
import {
  verifyMeta,
  verifyMetaChallenge,
  verifyWebhook,
  verifyWhatsApp,
} from "../src/index.js";
import { bytesToHex } from "../src/utils/encoding.js";

describe("Meta / WhatsApp Webhook Verifier", () => {
  const secret = "meta_app_secret_999";
  const body = JSON.stringify({
    object: "whatsapp_business_account",
    entry: [{ id: "123" }],
  });

  it("should verify valid Meta / WhatsApp SHA256 signature", async () => {
    const hmac = await computeHmacSha256(secret, body);
    const signature = `sha256=${bytesToHex(hmac)}`;

    const req = {
      headers: { "x-hub-signature-256": signature },
      body,
    };

    const metaRes = await verifyMeta(req, secret);
    const whatsappRes = await verifyWhatsApp(req, secret);

    expect(metaRes.valid).toBe(true);
    expect(metaRes.provider).toBe("meta");
    expect(whatsappRes.valid).toBe(true);
  });

  it("should verify valid Meta SHA1 signature (x-hub-signature fallback)", async () => {
    const hmac1 = await computeHmacSha1(secret, body);
    const signature = `sha1=${bytesToHex(hmac1)}`;

    const req = {
      headers: { "x-hub-signature": signature },
      body,
    };

    const res = await verifyMeta(req, secret);
    expect(res.valid).toBe(true);
  });

  it("should reject invalid Meta signature", async () => {
    const req = {
      headers: { "x-hub-signature-256": "sha256=invalid_hex" },
      body,
    };
    const result = await verifyWebhook("meta", req, secret);
    expect(result.valid).toBe(false);
    expect(result.code).toBe("INVALID_SIGNATURE");
  });

  it("should handle verifyMetaChallenge GET handshake correctly", () => {
    const verifyToken = "my_custom_verify_token_123";
    const queryParams = {
      "hub.mode": "subscribe",
      "hub.challenge": "challenge_code_777",
      "hub.verify_token": verifyToken,
    };

    const res = verifyMetaChallenge(queryParams, verifyToken);
    expect(res.valid).toBe(true);
    expect(res.challenge).toBe("challenge_code_777");
  });

  it("should reject verifyMetaChallenge with token mismatch or invalid mode", () => {
    const verifyToken = "my_custom_verify_token_123";

    const mismatchRes = verifyMetaChallenge(
      {
        "hub.mode": "subscribe",
        "hub.challenge": "777",
        "hub.verify_token": "wrong",
      },
      verifyToken,
    );
    expect(mismatchRes.valid).toBe(false);
    expect(mismatchRes.reason).toContain("Verify token mismatch");

    const invalidModeRes = verifyMetaChallenge(
      {
        "hub.mode": "invalid",
        "hub.challenge": "777",
        "hub.verify_token": verifyToken,
      },
      verifyToken,
    );
    expect(invalidModeRes.valid).toBe(false);
  });
});
