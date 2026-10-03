import { describe, expect, it } from "vitest";
import { verifyEcdsaP256Sha256, verifySendGrid } from "../src/index.js";
import { signWebhook } from "../src/testing.js";

describe("SendGrid Event Webhook Verifier", () => {
  // Vectors from @sendgrid/eventwebhook's own test suite.
  const PUBLIC_KEY =
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE83T4O/n84iotIvIW4mdBgQ/7dAfSmpqIM8kF9mN1flpVKS3GRqe62gw+2fNNRaINXvVpiglSI8eNEc6wEA3F+g==";
  const SIGNATURE =
    "MEUCIGHQVtGj+Y3LkG9fLcxf3qfI10QysgDWmMOVmxG0u6ZUAiEAyBiXDWzM+uOe5W0JuG+luQAbPIqHh89M15TluLtEZtM=";
  const TIMESTAMP = "1600112502";
  const PAYLOAD =
    JSON.stringify([
      {
        email: "hello@world.com",
        event: "dropped",
        reason: "Bounced Address",
        sg_event_id: "ZHJvcC0xMDk5NDkxOS1MUnpYbF9OSFN0T0doUTRrb2ZTbV9BLTA",
        sg_message_id:
          "LRzXl_NHStOGhQ4kofSm_A.filterdrecv-p3mdw1-756b745b58-kmzbl-18-5F5FC76C-9.0",
        "smtp-id": "<LRzXl_NHStOGhQ4kofSm_A@ismtpd0039p1iad1.sendgrid.net>",
        timestamp: 1600112492,
      },
    ]) + "\r\n";
  const headers = {
    "X-Twilio-Email-Event-Webhook-Signature": SIGNATURE,
    "X-Twilio-Email-Event-Webhook-Timestamp": TIMESTAMP,
  };
  const now = 1600112502;

  it("verifies SendGrid's published vector", async () => {
    const result = await verifySendGrid(
      { headers, body: PAYLOAD },
      PUBLIC_KEY,
      {
        now,
      },
    );
    expect(result.valid).toBe(true);
    expect(result.eventType).toBe("dropped");
    expect(result.event?.[0].email).toBe("hello@world.com");
  });

  it("verifies the multi-event vector", async () => {
    const events = [
      {
        email: "invalid@gmail.com",
        event: "processed",
        send_at: 0,
        sg_event_id:
          "cHJvY2Vzc2VkLTE5OTQyMTEyLXFOd0JMZ1BRUWpXNkRKdktRd1NBYnctMA",
        sg_message_id:
          "qNwBLgPQQjW6DJvKQwSAbw.filterdrecv-canary-547b64655b-cw6zx-1-6089EA4A-56.0",
        "smtp-id": "<qNwBLgPQQjW6DJvKQwSAbw@ismtpd0178p1mdw1.sendgrid.net>",
        timestamp: 1619651146,
      },
      {
        email: "invalid@gmail.com",
        event: "bounce",
        ip: "167.89.101.76",
        reason:
          "552 5.2.2 The email account that you tried to reach is over quota and inactive. Please direct the recipient to https://support.google.com/mail/?p=OverQuotaPerm c17si1130468pgv.34 - gsmtp",
        sg_event_id: "Ym91bmNlLTAtMTk5NDIxMTItcU53QkxnUFFRalc2REp2S1F3U0Fidy0w",
        sg_message_id:
          "qNwBLgPQQjW6DJvKQwSAbw.filterdrecv-canary-547b64655b-cw6zx-1-6089EA4A-56.0",
        "smtp-id": "<qNwBLgPQQjW6DJvKQwSAbw@ismtpd0178p1mdw1.sendgrid.net>",
        status: "5.2.2",
        timestamp: 1619651147,
        tls: 1,
        type: "blocked",
      },
    ];
    const body = JSON.stringify(events).split("},{").join("},\r\n{") + "\r\n";
    const result = await verifySendGrid(
      {
        headers: {
          "x-twilio-email-event-webhook-signature":
            "MEYCIQC/I4o6vCgqRYrTljjoVWB/GRWNtxeePlLMHr3x9ETeRQIhAIpV+03nREPTTHWSW0wIOA0EoMPdcNgXa70yCaqDJlu5",
          "x-twilio-email-event-webhook-timestamp": "1619651159",
        },
        body,
      },
      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQ4LIFtWztlsF7skFqOncjD1lun4H5w8XOhyOArHW9RcIx/FfEzx6cikC/yPfUvwaX/JScE7Fc9CJD2afQ9Ok3Q==",
      { now: 1619651159 },
    );
    expect(result.valid).toBe(true);
  });

  it("accepts the key as a PEM block", async () => {
    const pem = `-----BEGIN PUBLIC KEY-----\n${PUBLIC_KEY}\n-----END PUBLIC KEY-----\n`;
    const result = await verifySendGrid({ headers, body: PAYLOAD }, pem, {
      now,
    });
    expect(result.valid).toBe(true);
  });

  it("rejects another key, a modified payload and a changed timestamp", async () => {
    const otherKey =
      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqTxd43gyp8IOEto2LdIfjRQrIbsd4SXZkLW6jDutdhXSJCWHw8REntlo7aNDthvj+y7GjUuFDb/R1NGe1OPzpA==";
    expect(
      (await verifySendGrid({ headers, body: PAYLOAD }, otherKey, { now }))
        .code,
    ).toBe("INVALID_SIGNATURE");
    expect(
      (
        await verifySendGrid(
          { headers, body: PAYLOAD.replace("dropped", "delivered") },
          PUBLIC_KEY,
          { now },
        )
      ).code,
    ).toBe("INVALID_SIGNATURE");
    expect(
      (
        await verifySendGrid(
          {
            headers: {
              ...headers,
              "X-Twilio-Email-Event-Webhook-Timestamp": "1600112503",
            },
            body: PAYLOAD,
          },
          PUBLIC_KEY,
          { now },
        )
      ).code,
    ).toBe("INVALID_SIGNATURE");
  });

  it("rejects a key that is not an EC public key", async () => {
    const result = await verifySendGrid(
      { headers, body: PAYLOAD },
      "not-a-key",
      {
        now,
      },
    );
    expect(result.code).toBe("INVALID_SIGNATURE");
  });

  it("rejects missing headers and an expired timestamp", async () => {
    expect(
      (await verifySendGrid({ headers: {}, body: PAYLOAD }, PUBLIC_KEY)).code,
    ).toBe("MISSING_HEADER");
    expect(
      (
        await verifySendGrid({ headers, body: PAYLOAD }, PUBLIC_KEY, {
          now: now + 301,
        })
      ).code,
    ).toBe("EXPIRED_TIMESTAMP");
  });

  it("exposes the ECDSA helper", async () => {
    expect(
      await verifyEcdsaP256Sha256(
        PUBLIC_KEY,
        SIGNATURE,
        `${TIMESTAMP}${PAYLOAD}`,
      ),
    ).toBe(true);
    expect(await verifyEcdsaP256Sha256(PUBLIC_KEY, "AAAA", "x")).toBe(false);
  });

  it("round-trips signWebhook with a throwaway key pair", async () => {
    const hook = await signWebhook("sendgrid", {
      payload: [
        {
          email: "a@example.com",
          event: "open",
          sg_event_id: "1",
          timestamp: 1,
        },
      ],
    });
    const result = await verifySendGrid(hook, hook.secret);
    expect(result.valid).toBe(true);
    expect(result.eventType).toBe("open");
  });

  it("signs with a provided PKCS#8 key", async () => {
    const pair = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;
    const pkcs8 = Buffer.from(
      await crypto.subtle.exportKey("pkcs8", pair.privateKey),
    ).toString("base64");
    const spki = Buffer.from(
      await crypto.subtle.exportKey("spki", pair.publicKey),
    ).toString("base64");
    const hook = await signWebhook("sendgrid", {
      privateKey: pkcs8,
      payload: [],
    });
    expect(hook.secret).toBe(spki);
    expect((await verifySendGrid(hook, spki)).valid).toBe(true);
    await expect(
      signWebhook("sendgrid", { privateKey: "bm90LWEta2V5" }),
    ).rejects.toThrow(/PKCS#8/);
  });
});
