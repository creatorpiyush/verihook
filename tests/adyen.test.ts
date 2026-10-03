import { describe, expect, it } from "vitest";
import { verifyAdyen } from "../src/index.js";
import { signWebhook } from "../src/testing.js";

describe("Adyen Webhook Verifier", () => {
  // Vector from Adyen's "Verify HMAC signatures" docs, confirmed with
  // @adyen/api-library's HmacValidator.
  const hmacKey =
    "44782DEF547AAA06C910C43932B1EB0C71FC68D9D0C057550C48EC2ACF6BA056";
  const item = {
    additionalData: {
      hmacSignature: "coqCmt/IZ4E3CzPvMY8zTjQVL5hYJUiBRg8UU+iCWo0=",
    },
    amount: { currency: "EUR", value: 1130 },
    eventCode: "AUTHORISATION",
    eventDate: "2014-08-06T13:39:05+02:00",
    merchantAccountCode: "TestMerchant",
    merchantReference: "TestPayment-1407325143704",
    operations: ["CANCEL", "CAPTURE", "REFUND"],
    paymentMethod: "visa",
    pspReference: "7914073381342284",
    reason: "1234:7777:12/2012",
    success: "true",
  };
  const notification = (...items: object[]) =>
    JSON.stringify({
      live: "false",
      notificationItems: items.map((NotificationRequestItem) => ({
        NotificationRequestItem,
      })),
    });

  describe("standard notifications", () => {
    it("verifies Adyen's documented test vector", async () => {
      const result = await verifyAdyen(
        { headers: {}, body: notification(item) },
        hmacKey,
      );
      expect(result.valid).toBe(true);
      expect(result.eventType).toBe("AUTHORISATION");
      expect(
        result.event?.notificationItems?.[0].NotificationRequestItem
          .pspReference,
      ).toBe("7914073381342284");
    });

    it("accepts a lowercase hex key", async () => {
      const result = await verifyAdyen(
        { headers: {}, body: notification(item) },
        hmacKey.toLowerCase(),
      );
      expect(result.valid).toBe(true);
    });

    it("rejects a tampered signed field", async () => {
      const result = await verifyAdyen(
        { headers: {}, body: notification({ ...item, success: "false" }) },
        hmacKey,
      );
      expect(result.code).toBe("INVALID_SIGNATURE");
    });

    it("rejects the batch when any item fails", async () => {
      const bad = {
        ...item,
        additionalData: { hmacSignature: "AAAA" },
      };
      const result = await verifyAdyen(
        { headers: {}, body: notification(item, bad) },
        hmacKey,
      );
      expect(result.code).toBe("INVALID_SIGNATURE");
    });

    it("rejects an item without hmacSignature", async () => {
      const result = await verifyAdyen(
        {
          headers: {},
          body: notification({ ...item, additionalData: {} }),
        },
        hmacKey,
      );
      expect(result.code).toBe("MISSING_HEADER");
    });

    it("rejects a body with neither header nor notificationItems", async () => {
      for (const body of ["not json", "{}", '{"notificationItems":[]}']) {
        const result = await verifyAdyen({ headers: {}, body }, hmacKey);
        expect(result.code).toBe("MISSING_HEADER");
      }
    });

    it("round-trips signWebhook", async () => {
      const { additionalData: _, ...unsigned } = item;
      const hook = await signWebhook("adyen", {
        secret: hmacKey,
        payload: {
          live: "false",
          notificationItems: [{ NotificationRequestItem: unsigned }],
        },
      });
      expect(
        JSON.parse(hook.body).notificationItems[0].NotificationRequestItem
          .additionalData.hmacSignature,
      ).toBe(item.additionalData.hmacSignature);
      expect((await verifyAdyen(hook, hmacKey)).valid).toBe(true);
    });
  });

  describe("HmacSignature header webhooks", () => {
    // Base64 HMAC-SHA256 of the raw body, checked with HmacValidator.validateHMACSignature.
    const body =
      '{"data":{"balancePlatform":"YOUR_BALANCE_PLATFORM","id":"BA00000000000000000001"},"environment":"test","type":"balancePlatform.accountHolder.created"}';
    const headers = {
      HmacSignature: "bHTl+hmFBb8H+e53FagqeHkdttmJzDd3n2gi026qlo0=",
      Protocol: "HmacSHA256",
    };

    it("verifies a known-good signature", async () => {
      const result = await verifyAdyen({ headers, body }, hmacKey);
      expect(result.valid).toBe(true);
      expect(result.eventType).toBe("balancePlatform.accountHolder.created");
    });

    it("rejects a modified body", async () => {
      const result = await verifyAdyen(
        { headers, body: body.replace("test", "live") },
        hmacKey,
      );
      expect(result.code).toBe("INVALID_SIGNATURE");
    });

    it("round-trips signWebhook", async () => {
      const hook = await signWebhook("adyen", {
        secret: hmacKey,
        payload: { type: "balancePlatform.accountHolder.created" },
      });
      expect((await verifyAdyen(hook, hmacKey)).valid).toBe(true);
    });
  });

  it("rejects a key that is not hex", async () => {
    const result = await verifyAdyen(
      { headers: {}, body: notification(item) },
      "not-a-hex-key",
    );
    expect(result.code).toBe("INVALID_SECRET");
  });
});

describe("signWebhook secret formats", () => {
  it("explains a non-hex Adyen key and a PhonePe secret without a colon", async () => {
    await expect(signWebhook("adyen", { secret: "nope" })).rejects.toThrow(
      /hex HMAC key/,
    );
    await expect(signWebhook("phonepe", { secret: "nope" })).rejects.toThrow(
      /username:password/,
    );
  });
});
