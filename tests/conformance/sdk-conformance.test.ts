/**
 * Cross-SDK conformance: webhooks signed by the providers' official SDKs must verify
 * with verihook, and webhooks signed by `verihook/testing` must pass the official
 * SDKs' own verification. The SDKs are devDependencies only.
 */
import {
  sign as octokitSign,
  verify as octokitVerify,
} from "@octokit/webhooks-methods";
import fc from "fast-check";
import { WebhookSignatureValidator } from "mercadopago";
import Stripe from "stripe";
import { Webhook as SvixWebhook } from "svix";
import twilio from "twilio";
import { describe, expect, it } from "vitest";
import { verifyWebhook } from "../../src/index.js";
import { signWebhook } from "../../src/testing/sign.js";

const payload = JSON.stringify({
  id: "evt_conformance",
  type: "conformance.test",
  data: { amount: 4200, note: "ünïcødé ✓" },
});

describe("Stripe SDK (stripe)", () => {
  const stripe = new Stripe("sk_test_conformance");
  const secret = "whsec_conformance_secret";

  it("verihook verifies a header from stripe.webhooks.generateTestHeaderString", async () => {
    const header = stripe.webhooks.generateTestHeaderString({
      payload,
      secret,
    });
    const result = await verifyWebhook(
      "stripe",
      { headers: { "stripe-signature": header }, body: payload },
      secret,
    );
    expect(result.valid).toBe(true);
    expect(result.eventType).toBe("conformance.test");
  });

  it("stripe.webhooks.constructEventAsync accepts a verihook-signed webhook", async () => {
    const hook = await signWebhook("stripe", { secret, payload });
    const event = await stripe.webhooks.constructEventAsync(
      hook.body,
      hook.headers["stripe-signature"],
      secret,
    );
    expect(event.id).toBe("evt_conformance");
  });

  it("both reject a tampered body", async () => {
    const header = stripe.webhooks.generateTestHeaderString({
      payload,
      secret,
    });
    const tampered = payload.replace("4200", "4201");
    const result = await verifyWebhook(
      "stripe",
      { headers: { "stripe-signature": header }, body: tampered },
      secret,
    );
    expect(result.valid).toBe(false);
    await expect(
      stripe.webhooks.constructEventAsync(tampered, header, secret),
    ).rejects.toThrow();
  });
});

describe("GitHub SDK (@octokit/webhooks-methods)", () => {
  const secret = "github_conformance_secret";

  it("verihook verifies an X-Hub-Signature-256 from octokit sign()", async () => {
    const signature = await octokitSign(secret, payload);
    const result = await verifyWebhook(
      "github",
      {
        headers: {
          "x-hub-signature-256": signature,
          "x-github-event": "push",
        },
        body: payload,
      },
      secret,
    );
    expect(result.valid).toBe(true);
    expect(result.eventType).toBe("push");
  });

  it("octokit verify() accepts a verihook-signed webhook", async () => {
    const hook = await signWebhook("github", { secret, payload });
    await expect(
      octokitVerify(secret, hook.body, hook.headers["x-hub-signature-256"]),
    ).resolves.toBe(true);
  });

  it("both reject the wrong secret", async () => {
    const signature = await octokitSign("another_secret", payload);
    const result = await verifyWebhook(
      "github",
      { headers: { "x-hub-signature-256": signature }, body: payload },
      secret,
    );
    expect(result.valid).toBe(false);
    await expect(octokitVerify(secret, payload, signature)).resolves.toBe(
      false,
    );
  });
});

describe("Svix SDK (svix) - also covers Resend and Clerk", () => {
  const secret = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";

  it.each(["svix", "resend", "clerk"] as const)(
    "verihook (%s) verifies headers from Webhook.sign()",
    async (provider) => {
      const id = "msg_conformance";
      const timestamp = new Date();
      const signature = new SvixWebhook(secret).sign(id, timestamp, payload);
      const result = await verifyWebhook(
        provider,
        {
          headers: {
            "svix-id": id,
            "svix-timestamp": String(Math.floor(timestamp.getTime() / 1000)),
            "svix-signature": signature,
          },
          body: payload,
        },
        secret,
      );
      expect(result.valid).toBe(true);
    },
  );

  it("Webhook.verify() accepts a verihook-signed webhook", async () => {
    const hook = await signWebhook("svix", { secret, payload });
    // svix 2.x returns nothing on success and throws on failure.
    expect(() =>
      new SvixWebhook(secret).verify(hook.body, hook.headers),
    ).not.toThrow();
  });

  it("both reject a tampered body", async () => {
    const hook = await signWebhook("svix", { secret, payload });
    const tampered = payload.replace("4200", "4201");
    const result = await verifyWebhook(
      "svix",
      { headers: hook.headers, body: tampered },
      secret,
    );
    expect(result.valid).toBe(false);
    expect(() =>
      new SvixWebhook(secret).verify(tampered, hook.headers),
    ).toThrow();
  });
});

describe("Twilio SDK (twilio)", () => {
  const authToken = "twilio_conformance_token";
  const url = "https://hooks.example.com/twilio/sms?tenant=acme";
  const form = { Body: "Hello ✓", From: "+15551234567", To: "+15557654321" };

  it("verihook verifies a form signature from getExpectedTwilioSignature()", async () => {
    const signature = twilio.getExpectedTwilioSignature(authToken, url, form);
    const result = await verifyWebhook(
      "twilio",
      {
        headers: {
          "x-twilio-signature": signature,
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams(form).toString(),
        url,
      },
      authToken,
    );
    expect(result.valid).toBe(true);
  });

  it("validateRequest() accepts a verihook-signed form webhook", async () => {
    const hook = await signWebhook("twilio", {
      secret: authToken,
      form,
      url,
    });
    expect(
      twilio.validateRequest(
        authToken,
        hook.headers["x-twilio-signature"],
        hook.url,
        form,
      ),
    ).toBe(true);
  });

  it("validateRequestWithBody() accepts a verihook-signed JSON webhook", async () => {
    const hook = await signWebhook("twilio", {
      secret: authToken,
      payload,
      url,
    });
    expect(hook.url).toContain("bodySHA256=");
    expect(
      twilio.validateRequestWithBody(
        authToken,
        hook.headers["x-twilio-signature"],
        hook.url,
        hook.body,
      ),
    ).toBe(true);
  });

  it("both reject a changed form field", async () => {
    const signature = twilio.getExpectedTwilioSignature(authToken, url, form);
    const changed = { ...form, Body: "Hello?" };
    const result = await verifyWebhook(
      "twilio",
      {
        headers: {
          "x-twilio-signature": signature,
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams(changed).toString(),
        url,
      },
      authToken,
    );
    expect(result.valid).toBe(false);
    expect(twilio.validateRequest(authToken, signature, url, changed)).toBe(
      false,
    );
  });
});

describe("Mercado Pago SDK (mercadopago)", () => {
  /** The SDK's verdict, given what a framework hands it (decoded query value). */
  function sdkAccepts(hook: {
    url: string;
    headers: Record<string, string>;
    secret: string;
  }): boolean {
    try {
      WebhookSignatureValidator.validate({
        xSignature: hook.headers["x-signature"],
        xRequestId: hook.headers["x-request-id"],
        dataId: new URL(hook.url, "http://localhost").searchParams.get(
          "data.id",
        ),
        secret: hook.secret,
        toleranceSeconds: 300,
      });
      return true;
    } catch {
      return false;
    }
  }

  async function verihookAccepts(hook: {
    url: string;
    headers: Record<string, string>;
    body: string;
    secret: string;
  }): Promise<boolean> {
    const result = await verifyWebhook(
      "mercadopago",
      { headers: hook.headers, body: hook.body, url: hook.url },
      hook.secret,
    );
    return result.valid;
  }

  it("WebhookSignatureValidator accepts a verihook-signed webhook", async () => {
    const hook = await signWebhook("mercadopago", {
      secret: "mp_conformance_secret",
      payload: { type: "payment", data: { id: "ORD01ABC" } },
    });
    expect(sdkAccepts({ ...hook, secret: "mp_conformance_secret" })).toBe(true);
    expect(await verihookAccepts(hook)).toBe(true);
  });

  it("both give the same verdict on random and tampered deliveries", async () => {
    const id = fc.stringMatching(/^[A-Za-z0-9_-]{1,24}$/);
    await fc.assert(
      fc.asyncProperty(
        id,
        fc.option(fc.uuid(), { nil: undefined }),
        fc.string({ minLength: 1, maxLength: 24 }),
        fc.constantFrom(
          "none",
          "data.id",
          "data.id case",
          "request-id",
          "drop request-id",
          "secret",
          "body",
        ),
        async (dataId, requestId, secret, tamper) => {
          const hook = await signWebhook("mercadopago", {
            secret,
            payload: { type: "payment", data: { id: dataId } },
            ...(requestId ? { webhookId: requestId } : {}),
          });
          const headers = { ...hook.headers };
          let url = hook.url;
          let body = hook.body;
          let verifySecret = secret;
          const swapId = (next: string) => {
            const u = new URL(url);
            u.searchParams.set("data.id", next);
            url = u.toString();
          };
          if (tamper === "data.id") swapId(`${dataId}x`);
          if (tamper === "data.id case" && /[a-z]/i.test(dataId)) {
            swapId(
              dataId === dataId.toLowerCase()
                ? dataId.toUpperCase()
                : dataId.toLowerCase(),
            );
          }
          if (tamper === "request-id") headers["x-request-id"] = "changed";
          if (tamper === "drop request-id") delete headers["x-request-id"];
          if (tamper === "secret") verifySecret = `${secret}x`;
          if (tamper === "body") body = JSON.stringify({ forged: true });

          const changed = { url, headers, body, secret: verifySecret };
          expect(await verihookAccepts(changed)).toBe(sdkAccepts(changed));
        },
      ),
      { numRuns: 200 },
    );
  });
});
