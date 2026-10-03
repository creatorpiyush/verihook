/**
 * Cross-SDK conformance: webhooks signed by the providers' official SDKs must verify
 * with verihook, and webhooks signed by `verihook/testing` must pass the official
 * SDKs' own verification. The SDKs are devDependencies only.
 */
import {
  sign as octokitSign,
  verify as octokitVerify,
} from "@octokit/webhooks-methods";
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
