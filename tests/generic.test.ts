import { describe, expect, it } from "vitest";
import { computeHmac } from "../src/core/crypto.js";
import { verifyWebhook } from "../src/index.js";
import { bytesToBase64, bytesToHex } from "../src/utils/encoding.js";

describe("Generic Webhook Verifier", () => {
  const secret = "custom_generic_secret";
  const body = "custom raw body string";

  it("should verify custom header, hex encoding, sha256", async () => {
    const hmac = await computeHmac("SHA-256", secret, body);
    const signature = bytesToHex(hmac);

    const req = {
      headers: { "x-my-custom-sig": signature },
      body,
    };

    const result = await verifyWebhook("generic", req, secret, {
      headerName: "x-my-custom-sig",
      algorithm: "sha256",
      encoding: "hex",
    });

    expect(result.valid).toBe(true);
    expect(result.provider).toBe("generic");
  });

  it("should verify custom header with base64 encoding and sha512", async () => {
    const hmac = await computeHmac("SHA-512", secret, body);
    const signature = bytesToBase64(hmac);

    const req = {
      headers: { "x-signature-512": signature },
      body,
    };

    const result = await verifyWebhook("generic", req, secret, {
      headerName: "x-signature-512",
      algorithm: "sha512",
      encoding: "base64",
    });

    expect(result.valid).toBe(true);
  });

  it("should verify uppercase hex signature header in generic verifier", async () => {
    const hmac = await computeHmac("SHA-256", secret, body);
    const signature = bytesToHex(hmac).toUpperCase();

    const req = {
      headers: { "x-signature": signature },
      body,
    };

    const result = await verifyWebhook("generic", req, secret, {
      encoding: "hex",
    });

    expect(result.valid).toBe(true);
  });
  it("rejects an unknown algorithm or encoding instead of matching an empty signature", async () => {
    const req = { headers: { "x-signature": "\u00a0" }, body };
    for (const opts of [
      { encoding: "HEX" },
      { encoding: "base64url" },
      { algorithm: "md5" },
      { algorithm: "toString" },
    ]) {
      const result = await verifyWebhook("generic", req, secret, opts as never);
      expect(result.valid, JSON.stringify(opts)).toBe(false);
      expect(result.reason).toMatch(/Unsupported/);
    }
  });

  it("rejects a signature that is empty after trimming", async () => {
    const result = await verifyWebhook(
      "generic",
      { headers: { "x-signature": "\u00a0" }, body },
      secret,
    );
    expect(result.code).toBe("MISSING_HEADER");
  });
});
