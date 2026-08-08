import { describe, expect, it } from "vitest";
import { computeHmacSha1, computeHmacSha256 } from "../src/core/crypto.js";
import { verifyGitHub } from "../src/index.js";
import { bytesToHex } from "../src/utils/encoding.js";

describe("GitHub Webhook Verifier", () => {
  const secret = "github_webhook_secret_999";
  const body = JSON.stringify({ action: "opened", issue: { number: 42 } });

  it("should verify valid x-hub-signature-256 header", async () => {
    const hmac = await computeHmacSha256(secret, body);
    const hexSig = bytesToHex(hmac);
    const header = `sha256=${hexSig}`;

    const req = {
      headers: { "x-hub-signature-256": header },
      body,
    };

    const result = await verifyGitHub(req, secret);
    expect(result.valid).toBe(true);
    expect(result.provider).toBe("github");
  });

  it("should verify valid legacy x-hub-signature header (SHA-1)", async () => {
    const hmac = await computeHmacSha1(secret, body);
    const hexSig = bytesToHex(hmac);
    const header = `sha1=${hexSig}`;

    const req = {
      headers: { "x-hub-signature": header },
      body,
    };

    const result = await verifyGitHub(req, secret);
    expect(result.valid).toBe(true);
  });

  it("should reject invalid GitHub signature", async () => {
    const req = {
      headers: {
        "x-hub-signature-256": "sha256=000000000000000000000000000000000000",
      },
      body,
    };

    const result = await verifyGitHub(req, secret);
    expect(result.valid).toBe(false);
  });

  it("should verify signature header containing surrounding whitespace", async () => {
    const hmac = await computeHmacSha256(secret, body);
    const hexSig = bytesToHex(hmac);
    const header = ` sha256=${hexSig} \n`;

    const req = {
      headers: { "x-hub-signature-256": header },
      body,
    };

    const result = await verifyGitHub(req, secret);
    expect(result.valid).toBe(true);
  });
});
