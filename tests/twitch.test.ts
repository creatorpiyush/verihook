import { describe, expect, it } from "vitest";
import { MemoryDedupeStore, verifyTwitch } from "../src/index.js";
import { signWebhook } from "../src/testing.js";

describe("Twitch EventSub Webhook Verifier", () => {
  // Vector: hex HMAC-SHA256 of `<message id><timestamp><body>`.
  const secret = "twitch_secret";
  const body =
    '{"subscription":{"id":"f1c2a387-161a-49f9-a165-0f21d7a4e1c4","type":"channel.follow","version":"2","status":"enabled","condition":{"broadcaster_user_id":"1337"}},"event":{"user_id":"1234","user_login":"cool_user"}}';
  const headers = {
    "Twitch-Eventsub-Message-Id": "e76c6bd4-55c9-4987-8304-da1588d8988b",
    "Twitch-Eventsub-Message-Timestamp": "2023-07-19T14:56:51.634234626Z",
    "Twitch-Eventsub-Message-Signature":
      "sha256=1125caf1d37a76d064c75981eb1390fda7b55c60bdb5856baba375ff0c095635",
    "Twitch-Eventsub-Message-Type": "notification",
    "Twitch-Eventsub-Subscription-Type": "channel.follow",
  };
  const now = 1689778611; // 2023-07-19T14:56:51Z

  it("verifies a known-good signature with a nanosecond timestamp", async () => {
    const result = await verifyTwitch({ headers, body }, secret, { now });
    expect(result.valid).toBe(true);
    expect(result.timestamp).toBe(now);
    expect(result.eventType).toBe("channel.follow");
    expect(result.event?.event).toEqual({
      user_id: "1234",
      user_login: "cool_user",
    });
  });

  it("uses a 10-minute default tolerance", async () => {
    expect(
      (await verifyTwitch({ headers, body }, secret, { now: now + 590 })).valid,
    ).toBe(true);
    expect(
      (await verifyTwitch({ headers, body }, secret, { now: now + 601 })).code,
    ).toBe("EXPIRED_TIMESTAMP");
  });

  it("rejects a wrong secret, a modified body and a changed message id", async () => {
    expect((await verifyTwitch({ headers, body }, "other", { now })).code).toBe(
      "INVALID_SIGNATURE",
    );
    expect(
      (
        await verifyTwitch(
          { headers, body: body.replace("cool_user", "evil") },
          secret,
          { now },
        )
      ).code,
    ).toBe("INVALID_SIGNATURE");
    expect(
      (
        await verifyTwitch(
          {
            headers: { ...headers, "Twitch-Eventsub-Message-Id": "other" },
            body,
          },
          secret,
          { now },
        )
      ).code,
    ).toBe("INVALID_SIGNATURE");
  });

  it("rejects missing headers and an unparseable timestamp", async () => {
    expect((await verifyTwitch({ headers: {}, body }, secret)).code).toBe(
      "MISSING_HEADER",
    );
    expect(
      (
        await verifyTwitch(
          {
            headers: {
              ...headers,
              "Twitch-Eventsub-Message-Timestamp": "yesterday",
            },
            body,
          },
          secret,
        )
      ).code,
    ).toBe("MISSING_HEADER");
  });

  it("dedupes on the message id", async () => {
    const dedupeStore = new MemoryDedupeStore();
    const opts = { now, dedupeStore };
    expect((await verifyTwitch({ headers, body }, secret, opts)).valid).toBe(
      true,
    );
    expect((await verifyTwitch({ headers, body }, secret, opts)).code).toBe(
      "DUPLICATE_EVENT",
    );
  });

  it("verifies a callback verification challenge", async () => {
    const hook = await signWebhook("twitch", {
      secret,
      payload: {
        challenge: "pogchamp-kappa-360noscope-vohiyo",
        subscription: { type: "x" },
      },
      headers: {
        "twitch-eventsub-message-type": "webhook_callback_verification",
      },
    });
    const result = await verifyTwitch(hook, secret);
    expect(result.valid).toBe(true);
    expect(result.event?.challenge).toBe("pogchamp-kappa-360noscope-vohiyo");
  });
});
