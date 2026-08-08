import { describe, expect, it } from "vitest";
import { computeHmacSha256 } from "../src/core/crypto.js";
import { verifyPagerDuty } from "../src/index.js";
import { bytesToHex } from "../src/utils/encoding.js";

describe("PagerDuty Webhook Verifier", () => {
  const secret = "pagerduty_secret_key_111";
  const body = JSON.stringify({ event: { event_type: "incident.triggered" } });

  it("should verify valid PagerDuty signature", async () => {
    const hmac = await computeHmacSha256(secret, body);
    const signature = `v1=${bytesToHex(hmac)}`;

    const req = {
      headers: { "x-pagerduty-signature": signature },
      body,
    };

    const result = await verifyPagerDuty(req, secret);
    expect(result.valid).toBe(true);
    expect(result.provider).toBe("pagerduty");
  });

  it("should reject invalid signature", async () => {
    const req = {
      headers: { "x-pagerduty-signature": "v1=invalid_hex" },
      body,
    };

    const result = await verifyPagerDuty(req, secret);
    expect(result.valid).toBe(false);
    expect(result.code).toBe("INVALID_SIGNATURE");
  });
});
