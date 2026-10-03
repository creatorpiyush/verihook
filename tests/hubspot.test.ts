import { describe, expect, it } from "vitest";
import { verifyHubSpot } from "../src/index.js";
import { signWebhook } from "../src/testing.js";

describe("HubSpot Webhook Verifier", () => {
  // v1 / v2 vectors from @hubspot/api-client's signature tests.
  const clientSecret = "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy";
  const v1Body =
    '[{"eventId":1,"subscriptionId":12345,"portalId":62515,"occurredAt":1564113600000,"subscriptionType":"contact.creation","attemptNumber":0,"objectId":123,"changeSource":"CRM","changeFlag":"NEW","appId":54321}]';

  it("verifies a v1 signature", async () => {
    const result = await verifyHubSpot(
      {
        headers: {
          "X-HubSpot-Signature":
            "232db2615f3d666fe21a8ec971ac7b5402d33b9a925784df3ca654d05f4817de",
          "X-HubSpot-Signature-Version": "v1",
        },
        body: v1Body,
      },
      clientSecret,
    );
    expect(result.valid).toBe(true);
    expect(result.eventType).toBe("contact.creation");
    expect(result.event?.[0].portalId).toBe(62515);
  });

  it("verifies v2 signatures (with and without a body)", async () => {
    const withBody = await verifyHubSpot(
      {
        headers: {
          "x-hubspot-signature":
            "9569219f8ba981ffa6f6f16aa0f48637d35d728c7e4d93d0d52efaa512af7900",
          "x-hubspot-signature-version": "v2",
        },
        body: '{"example_field":"example_value"}',
        url: "https://www.example.com/webhook_uri",
      },
      clientSecret,
    );
    expect(withBody.valid).toBe(true);

    const get = await verifyHubSpot(
      {
        headers: {
          "x-hubspot-signature":
            "eee2dddcc73c94d699f5e395f4b9d454a069a6855fbfa152e91e88823087200e",
          "x-hubspot-signature-version": "v2",
        },
        body: "",
        method: "GET",
        url: "https://www.example.com/webhook_uri",
      },
      clientSecret,
    );
    expect(get.valid).toBe(true);
  });

  describe("v3", () => {
    // Cross-checked with @hubspot/api-client's Signature.getSignature("POST", "v3", ...).
    const headers = {
      "x-hubspot-signature-v3": "pGaqipPiYpnRzTHQquj/LJH83HMaMUaJ132HqlEOjx8=",
      "x-hubspot-request-timestamp": "1700000000000",
    };
    const now = 1700000000;

    it("verifies a signature and decodes the listed URI escapes", async () => {
      for (const url of [
        "https://www.example.com/webhook_uri?x=a:b",
        "https://www.example.com/webhook_uri?x=a%3Ab",
        "https://www.example.com/webhook_uri?x=a%3ab",
      ]) {
        const result = await verifyHubSpot(
          { headers, body: v1Body, url },
          clientSecret,
          {
            now,
          },
        );
        expect(result.valid).toBe(true);
      }
    });

    it("rebuilds the URL from the host header", async () => {
      const result = await verifyHubSpot(
        {
          headers: { ...headers, host: "www.example.com" },
          body: v1Body,
          url: "/webhook_uri?x=a:b",
        },
        clientSecret,
        { now },
      );
      expect(result.valid).toBe(true);
    });

    it("rejects a wrong secret, a different URL and an expired timestamp", async () => {
      const req = {
        headers,
        body: v1Body,
        url: "https://www.example.com/webhook_uri?x=a:b",
      };
      expect((await verifyHubSpot(req, "other", { now })).code).toBe(
        "INVALID_SIGNATURE",
      );
      const moved = await verifyHubSpot(
        { ...req, url: "https://evil.example.com/webhook_uri?x=a:b" },
        clientSecret,
        { now },
      );
      expect(moved.code).toBe("INVALID_SIGNATURE");
      expect(moved.reason).toContain("evil.example.com");
      expect(
        (await verifyHubSpot(req, clientSecret, { now: now + 301 })).code,
      ).toBe("EXPIRED_TIMESTAMP");
    });

    it("rejects a missing timestamp or URL", async () => {
      expect(
        (
          await verifyHubSpot(
            {
              headers: {
                "x-hubspot-signature-v3": headers["x-hubspot-signature-v3"],
              },
              body: v1Body,
              url: "https://www.example.com/",
            },
            clientSecret,
          )
        ).code,
      ).toBe("MISSING_HEADER");
      expect(
        (await verifyHubSpot({ headers, body: v1Body }, clientSecret, { now }))
          .code,
      ).toBe("MISSING_URL");
    });
  });

  it("rejects missing headers and unknown versions", async () => {
    expect(
      (await verifyHubSpot({ headers: {}, body: v1Body }, clientSecret)).code,
    ).toBe("MISSING_HEADER");
    expect(
      (
        await verifyHubSpot(
          {
            headers: {
              "x-hubspot-signature": "x",
              "x-hubspot-signature-version": "v9",
            },
            body: v1Body,
          },
          clientSecret,
        )
      ).reason,
    ).toContain("v9");
    expect(
      (
        await verifyHubSpot(
          {
            headers: {
              "x-hubspot-signature": "x",
              "x-hubspot-signature-version": "v2",
            },
            body: v1Body,
          },
          clientSecret,
        )
      ).code,
    ).toBe("MISSING_URL");
  });

  it("round-trips signWebhook (v3)", async () => {
    const hook = await signWebhook("hubspot", {
      secret: clientSecret,
      url: "https://hooks.example.com/hubspot?portal=1:2",
      payload: [{ subscriptionType: "deal.creation" }],
    });
    const result = await verifyHubSpot(hook, clientSecret);
    expect(result.valid).toBe(true);
    expect(result.eventType).toBe("deal.creation");
  });
});
