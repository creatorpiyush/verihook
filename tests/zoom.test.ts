import { describe, expect, it } from "vitest";
import { computeHmacSha256 } from "../src/core/crypto.js";
import { verifyZoom } from "../src/index.js";
import { bytesToHex } from "../src/utils/encoding.js";

describe("Zoom Webhook Verifier", () => {
  const secret = "zoom_secret_token_555";
  const body = JSON.stringify({ event: "meeting.started" });
  const timestamp = 1700000000;

  it("should verify valid Zoom signature", async () => {
    const msg = `v0:${timestamp}:${body}`;
    const hmac = await computeHmacSha256(secret, msg);
    const signature = `v0=${bytesToHex(hmac)}`;

    const req = {
      headers: {
        "x-zm-signature": signature,
        "x-zm-request-timestamp": String(timestamp),
      },
      body,
    };

    const result = await verifyZoom(req, secret, { now: timestamp + 5 });
    expect(result.valid).toBe(true);
    expect(result.provider).toBe("zoom");
  });

  it("should verify Zoom signature with 13-digit millisecond timestamp and options.now in ms", async () => {
    const msTimestamp = 1700000000123;
    const msg = `v0:${msTimestamp}:${body}`;
    const hmac = await computeHmacSha256(secret, msg);
    const signature = `v0=${bytesToHex(hmac)}`;

    const req = {
      headers: {
        "x-zm-signature": signature,
        "x-zm-request-timestamp": String(msTimestamp),
      },
      body,
    };

    const result = await verifyZoom(req, secret, { now: msTimestamp + 2000 });
    expect(result.valid).toBe(true);
    expect(result.provider).toBe("zoom");
  });
});
