import { describe, expect, it } from "vitest";
import { computeHmacSha256 } from "../src/core/crypto.js";
import { verifySquare } from "../src/index.js";
import { bytesToBase64 } from "../src/utils/encoding.js";

describe("Square Webhook Verifier", () => {
  const secret = "square_sig_key_333";
  const url = "https://example.com/square/events";
  const body = JSON.stringify({ type: "payment.updated" });

  it("should verify valid Square signature", async () => {
    const payloadToSign = url + body;
    const hmac = await computeHmacSha256(secret, payloadToSign);
    const signature = bytesToBase64(hmac);

    const req = {
      headers: { "x-square-hmacsha256-signature": signature },
      body,
      url,
    };

    const result = await verifySquare(req, secret);
    expect(result.valid).toBe(true);
    expect(result.provider).toBe("square");
  });
});
