import { describe, expect, it } from "vitest";
import { computeHmacSha256 } from "../src/core/crypto.js";
import { verifyPaddle } from "../src/index.js";
import { bytesToHex } from "../src/utils/encoding.js";

describe("Paddle Webhook Verifier", () => {
  const secret = "paddle_secret_key_555";
  const timestamp = 1700000000;
  const body = JSON.stringify({ event_type: "transaction.completed" });

  it("should verify valid Paddle signature", async () => {
    const payloadToSign = `${timestamp}:${body}`;
    const hmac = await computeHmacSha256(secret, payloadToSign);
    const signatureHex = bytesToHex(hmac);
    const header = `ts=${timestamp};h1=${signatureHex}`;

    const req = {
      headers: { "paddle-signature": header },
      body,
    };

    const result = await verifyPaddle(req, secret, { now: timestamp + 5 });
    expect(result.valid).toBe(true);
    expect(result.provider).toBe("paddle");
    expect(result.timestamp).toBe(timestamp);
  });

  it("matches the header format from Paddle's docs (ts=...;h1=...)", async () => {
    const hmac = await computeHmacSha256(secret, `${timestamp}:${body}`);
    const result = await verifyPaddle(
      {
        headers: {
          "paddle-signature": `ts=${timestamp};h1=${bytesToHex(hmac)}`,
        },
        body,
      },
      secret,
      { now: timestamp },
    );
    expect(result.valid).toBe(true);
  });

  it("still accepts the legacy h= key", async () => {
    const hmac = await computeHmacSha256(secret, `${timestamp}:${body}`);
    const result = await verifyPaddle(
      {
        headers: {
          "paddle-signature": `ts=${timestamp};h=${bytesToHex(hmac)}`,
        },
        body,
      },
      secret,
      { now: timestamp },
    );
    expect(result.valid).toBe(true);
  });

  it("rejects a tampered body signed with h1", async () => {
    const hmac = await computeHmacSha256(secret, `${timestamp}:${body}`);
    const result = await verifyPaddle(
      {
        headers: {
          "paddle-signature": `ts=${timestamp};h1=${bytesToHex(hmac)}`,
        },
        body: body.replace("completed", "refunded"),
      },
      secret,
      { now: timestamp },
    );
    expect(result.valid).toBe(false);
    expect(result.code).toBe("INVALID_SIGNATURE");
  });

  it("should reject expired timestamp outside tolerance window", async () => {
    const req = {
      headers: { "paddle-signature": `ts=${timestamp};h=abc` },
      body,
    };

    const result = await verifyPaddle(req, secret, {
      now: timestamp + 500,
      tolerance: 300,
    });
    expect(result.valid).toBe(false);
    expect(result.code).toBe("EXPIRED_TIMESTAMP");
  });
});
