import crypto from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { computeCrc32, computeHmacSha256 } from "../src/core/crypto.js";
import { clearPayPalCertCache, verifyPayPal } from "../src/index.js";
import { bytesToBase64, bytesToHex } from "../src/utils/encoding.js";

describe("PayPal Webhook Verifier", () => {
  const webhookId = "WH-1234567890";
  const body = JSON.stringify({
    event_type: "PAYMENT.CAPTURE.COMPLETED",
    id: "WH-EVT-100",
  });
  const transId = "trans_123";
  const transTime = "2026-07-26T12:00:00Z";
  const expectedPayload = `${transId}|${transTime}|${webhookId}|${computeCrc32(body)}`;

  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  const pemPubKey = publicKey
    .export({ type: "spki", format: "pem" })
    .toString();

  function rsaSign(data: string): string {
    const signer = crypto.createSign("RSA-SHA256");
    signer.update(data);
    return bytesToBase64(signer.sign(privateKey));
  }

  function makeReq(sig: string, certUrl?: string) {
    return {
      headers: {
        "paypal-transmission-id": transId,
        "paypal-transmission-time": transTime,
        "paypal-transmission-sig": sig,
        ...(certUrl ? { "paypal-cert-url": certUrl } : {}),
      },
      body,
    };
  }

  afterEach(() => {
    vi.restoreAllMocks();
    clearPayPalCertCache();
  });

  it("verifies an RSA signature against a pinned PEM public key", async () => {
    const result = await verifyPayPal(
      makeReq(rsaSign(expectedPayload)),
      pemPubKey,
      { webhookId },
    );
    expect(result.valid).toBe(true);
    expect(result.provider).toBe("paypal");
  });

  it("rejects an invalid RSA signature", async () => {
    const result = await verifyPayPal(
      makeReq("invalid_rsa_sig"),
      "-----BEGIN PUBLIC KEY-----...",
      { webhookId },
    );
    expect(result.valid).toBe(false);
    expect(result.code).toBe("INVALID_SIGNATURE");
    expect(result.reason).toContain(
      "PayPal RSA-SHA256 signature verification failed",
    );
  });

  it("rejects HMAC signatures forged with the webhook ID (no HMAC fallback)", async () => {
    const forged = bytesToHex(
      await computeHmacSha256(webhookId, expectedPayload),
    );
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const withoutCert = await verifyPayPal(makeReq(forged), webhookId);
    expect(withoutCert.valid).toBe(false);
    expect(withoutCert.code).toBe("MISSING_HEADER");

    const withSecret = await verifyPayPal(makeReq(forged), webhookId, {
      webhookId,
    });
    expect(withSecret.valid).toBe(false);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("rejects cert URLs that are not exact PayPal certificate hosts", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    for (const certUrl of [
      "https://evil.com/fake-cert",
      "https://attacker.paypal.com/cert",
      "https://api.paypal.com.evil.com/cert",
      "http://api.paypal.com/v1/notifications/certs/CERT-1",
      "https://api.paypal.com:8443/v1/notifications/certs/CERT-1",
    ]) {
      const result = await verifyPayPal(
        makeReq(rsaSign(expectedPayload), certUrl),
        "",
        { webhookId },
      );
      expect(result.valid).toBe(false);
      expect(result.code).toBe("INVALID_SIGNATURE");
    }
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("fetches the certificate from a trusted host once and caches it", async () => {
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(new Response(pemPubKey, { status: 200 }));
    const certUrl =
      "https://api-m.sandbox.paypal.com/v1/notifications/certs/CERT-CACHE";

    for (let i = 0; i < 2; i++) {
      const result = await verifyPayPal(
        makeReq(rsaSign(expectedPayload), certUrl),
        "",
        { webhookId },
      );
      expect(result.valid).toBe(true);
    }
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it("fails closed when the certificate fetch fails", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("timeout"));
    const result = await verifyPayPal(
      makeReq(
        rsaSign(expectedPayload),
        "https://api.paypal.com/v1/notifications/certs/CERT-DOWN",
      ),
      "",
      { webhookId },
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("Unable to fetch");
  });

  it("requires a webhook ID", async () => {
    const result = await verifyPayPal(
      makeReq(rsaSign(expectedPayload)),
      pemPubKey,
    );
    expect(result.valid).toBe(false);
    expect(result.code).toBe("INVALID_SECRET");
  });
});
