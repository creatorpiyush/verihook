import { describe, expect, it } from "vitest";
import { computeHmacSha256 } from "../src/core/crypto.js";
import { MemoryDedupeStore, extractEventId } from "../src/core/dedupe.js";
import {
  WebhookErrorCode,
  verifyWebhook,
  verifyWebhookOrThrow,
} from "../src/index.js";
import { bytesToHex } from "../src/utils/encoding.js";

describe("Replay Protection & Deduplication Store", () => {
  describe("MemoryDedupeStore", () => {
    it("should return false on first key registration and true on duplicate key", () => {
      const store = new MemoryDedupeStore({ ttlMs: 10000 });
      expect(store.hasOrSet("evt_1", 10000)).toBe(false);
      expect(store.hasOrSet("evt_1", 10000)).toBe(true);
      expect(store.size).toBe(1);
    });

    it("should expire key after ttlMs duration", async () => {
      const store = new MemoryDedupeStore({ ttlMs: 10 });
      expect(store.hasOrSet("evt_expire", 10)).toBe(false);
      expect(store.hasOrSet("evt_expire", 10)).toBe(true);

      // Wait for expiration
      await new Promise((r) => setTimeout(r, 20));

      // Key should be expired and re-added as new
      expect(store.hasOrSet("evt_expire", 10)).toBe(false);
    });

    it("should purge all stored keys when clear() is called", () => {
      const store = new MemoryDedupeStore();
      store.hasOrSet("key_1", 1000);
      store.hasOrSet("key_2", 1000);
      expect(store.size).toBe(2);

      store.clear();
      expect(store.size).toBe(0);
      expect(store.hasOrSet("key_1", 1000)).toBe(false);
    });

    it("should evict oldest entry when maxSize limit is exceeded", () => {
      const store = new MemoryDedupeStore({ maxSize: 2, ttlMs: 10000 });
      store.hasOrSet("key_1");
      store.hasOrSet("key_2");
      expect(store.size).toBe(2);

      // Exceed maxSize capacity
      store.hasOrSet("key_3");
      expect(store.size).toBe(2);

      // key_1 was evicted, key_2 and key_3 remain
      expect(store.hasOrSet("key_1")).toBe(false);
      expect(store.hasOrSet("key_3")).toBe(true);
    });

    it("should refresh LRU position on duplicate access hit so active duplicate keys avoid early eviction", () => {
      const store = new MemoryDedupeStore({ maxSize: 2, ttlMs: 10000 });
      store.hasOrSet("key_1"); // key_1 inserted
      store.hasOrSet("key_2"); // key_2 inserted

      // Duplicate hit on key_1 refreshes its LRU order position
      expect(store.hasOrSet("key_1")).toBe(true);

      // Insert key_3 -> should evict key_2 (oldest), preserving key_1
      store.hasOrSet("key_3");
      expect(store.hasOrSet("key_1")).toBe(true); // key_1 retained
      expect(store.hasOrSet("key_2")).toBe(false); // key_2 evicted
    });
  });

  describe("extractEventId", () => {
    it("should extract svix-id header for Svix / Resend / Clerk / WorkOS", async () => {
      const id = await extractEventId("svix", {
        headers: { "svix-id": "msg_test_123" },
        rawBody: "{}",
      });
      expect(id).toBe("msg_test_123");
    });

    it("ignores unsigned ID headers (x-github-delivery, x-shopify-webhook-id, svix-id on other providers)", async () => {
      const body = "plain text non json body";
      const digest = await extractEventId("github", {
        headers: {},
        rawBody: body,
      });
      for (const headers of [
        { "x-github-delivery": "guid-github-123" },
        { "svix-id": "msg_spoofed" },
        { "webhook-id": "msg_spoofed" },
        { "paypal-transmission-id": "tx_spoofed" },
      ]) {
        expect(await extractEventId("github", { headers, rawBody: body })).toBe(
          digest,
        );
      }
      expect(
        await extractEventId("shopify", {
          headers: { "x-shopify-webhook-id": "shopify_evt_99" },
          rawBody: JSON.stringify({ id: 4242 }),
        }),
      ).toHaveLength(64);
    });

    it("should extract paypal-transmission-id header for PayPal", async () => {
      const id = await extractEventId("paypal", {
        headers: { "paypal-transmission-id": "tx_paypal_007" },
        rawBody: "{}",
      });
      expect(id).toBe("tx_paypal_007");
    });

    it("should extract JSON id, event_id, or msg_id from body payload", async () => {
      const id1 = await extractEventId("stripe", {
        headers: {},
        rawBody: JSON.stringify({ id: "evt_stripe_100" }),
      });
      expect(id1).toBe("evt_stripe_100");

      const id2 = await extractEventId("generic", {
        headers: {},
        rawBody: JSON.stringify({ event_id: "evt_custom_200" }),
      });
      expect(id2).toBe("evt_custom_200");

      const id3 = await extractEventId("pagerduty", {
        headers: {},
        rawBody: JSON.stringify({ messages: [{ id: "pd_msg_1" }] }),
      });
      expect(id3).toBe("pd_msg_1");
    });

    it("should extract msg_id or signature fallback headers", async () => {
      const idMsg = await extractEventId("generic", {
        headers: {},
        rawBody: JSON.stringify({ msg_id: "msg_custom_300" }),
      });
      expect(idMsg).toBe("msg_custom_300");

      // Signature headers are not used: their format allows variations that still verify.
      const idTwilio = await extractEventId("twilio", {
        headers: { "x-twilio-signature": "twilio_sig_hash" },
        rawBody: "unparseable_invalid_json{",
      });
      expect(idTwilio).toHaveLength(64);
    });

    it("uses the signed Mailgun token over unsigned body fields", async () => {
      const id = await extractEventId("mailgun", {
        headers: {},
        rawBody: JSON.stringify({
          id: "unsigned_top_level",
          signature: { timestamp: "1", token: "mg_token_1", signature: "x" },
        }),
      });
      expect(id).toBe("mg_token_1");

      const form = await extractEventId("mailgun", {
        headers: { "content-type": "application/x-www-form-urlencoded" },
        rawBody: "timestamp=1&token=mg_form_token&signature=x",
      });
      expect(form).toBe("mg_form_token");
    });

    it("should fallback to SHA-256 hash when no header or JSON ID is present", async () => {
      const id = await extractEventId("generic", {
        headers: {},
        rawBody: "plain text non json body",
      });
      expect(typeof id).toBe("string");
      expect(id).toHaveLength(64); // hex sha256
    });
  });

  describe("verifyWebhook with dedupeStore", () => {
    const secret = "stripe_dedupe_secret";
    const bodyStr = JSON.stringify({
      id: "evt_stripe_dedupe_1",
      type: "payment_intent.succeeded",
    });
    const timestamp = 1700000000;

    async function makeStripeHeader() {
      const payloadToSign = `${timestamp}.${bodyStr}`;
      const hmac = await computeHmacSha256(secret, payloadToSign);
      return `t=${timestamp},v1=${bytesToHex(hmac)}`;
    }

    it("should pass initial request and reject duplicate request with DUPLICATE_EVENT code", async () => {
      const signatureHeader = await makeStripeHeader();
      const dedupeStore = new MemoryDedupeStore();

      const req = {
        headers: { "stripe-signature": signatureHeader },
        body: bodyStr,
      };

      // First verification call
      const res1 = await verifyWebhook("stripe", req, secret, {
        now: timestamp,
        dedupeStore,
      });
      expect(res1.valid).toBe(true);

      // Duplicate verification call
      const res2 = await verifyWebhook("stripe", req, secret, {
        now: timestamp,
        dedupeStore,
      });
      expect(res2.valid).toBe(false);
      expect(res2.code).toBe(WebhookErrorCode.DUPLICATE_EVENT);
      expect(res2.reason).toContain("Duplicate webhook event");
    });

    it("rejects a replay that adds or changes unsigned ID headers", async () => {
      const dedupeStore = new MemoryDedupeStore();
      const stripeHeader = await makeStripeHeader();
      const first = await verifyWebhook(
        "stripe",
        { headers: { "stripe-signature": stripeHeader }, body: bodyStr },
        secret,
        { now: timestamp, dedupeStore },
      );
      expect(first.valid).toBe(true);
      const replay = await verifyWebhook(
        "stripe",
        {
          headers: { "stripe-signature": stripeHeader, "svix-id": "msg_new" },
          body: bodyStr,
        },
        secret,
        { now: timestamp, dedupeStore },
      );
      expect(replay.code).toBe(WebhookErrorCode.DUPLICATE_EVENT);

      const ghSecret = "gh_dedupe_secret";
      const ghBody = JSON.stringify({ ref: "refs/heads/main" });
      const ghSig = `sha256=${bytesToHex(await computeHmacSha256(ghSecret, ghBody))}`;
      const send = (delivery: string) =>
        verifyWebhook(
          "github",
          {
            headers: {
              "x-hub-signature-256": ghSig,
              "x-github-delivery": delivery,
            },
            body: ghBody,
          },
          ghSecret,
          { dedupeStore },
        );
      expect((await send("guid-1")).valid).toBe(true);
      expect((await send("guid-2")).code).toBe(
        WebhookErrorCode.DUPLICATE_EVENT,
      );
    });

    it("should support explicit eventId option override", async () => {
      const signatureHeader = await makeStripeHeader();
      const dedupeStore = new MemoryDedupeStore();

      const req = {
        headers: { "stripe-signature": signatureHeader },
        body: bodyStr,
      };

      const res1 = await verifyWebhook("stripe", req, secret, {
        now: timestamp,
        dedupeStore,
        eventId: "custom_unique_event_id",
      });
      expect(res1.valid).toBe(true);

      const res2 = await verifyWebhook("stripe", req, secret, {
        now: timestamp,
        dedupeStore,
        eventId: "custom_unique_event_id",
      });
      expect(res2.valid).toBe(false);
      expect(res2.code).toBe(WebhookErrorCode.DUPLICATE_EVENT);
    });

    it("should throw WebhookVerificationError with DUPLICATE_EVENT on duplicate call using verifyWebhookOrThrow", async () => {
      const signatureHeader = await makeStripeHeader();
      const dedupeStore = new MemoryDedupeStore();

      const req = {
        headers: { "stripe-signature": signatureHeader },
        body: bodyStr,
      };

      await verifyWebhookOrThrow("stripe", req, secret, {
        now: timestamp,
        dedupeStore,
      });

      await expect(
        verifyWebhookOrThrow("stripe", req, secret, {
          now: timestamp,
          dedupeStore,
        }),
      ).rejects.toThrow(/Duplicate webhook event/);
    });

    it("should NOT record invalid signature requests into dedupeStore", async () => {
      const dedupeStore = new MemoryDedupeStore();
      const req = {
        headers: { "stripe-signature": "t=1700000000,v1=bad_signature" },
        body: bodyStr,
      };

      const res1 = await verifyWebhook("stripe", req, secret, {
        now: timestamp,
        dedupeStore,
      });
      expect(res1.valid).toBe(false);
      expect(res1.code).toBe(WebhookErrorCode.INVALID_SIGNATURE);
      expect(dedupeStore.size).toBe(0);
    });
  });
});
