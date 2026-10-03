import { describe, expect, it } from "vitest";
import { verifyTelegram } from "../src/index.js";
import { signWebhook } from "../src/testing.js";

describe("Telegram Webhook Verifier", () => {
  const secret = "My_Secret-Token_123";
  const body = JSON.stringify({
    update_id: 10000,
    message: {
      message_id: 1,
      chat: { id: 42, type: "private" },
      text: "/start",
    },
  });

  it("accepts the matching secret token", async () => {
    const result = await verifyTelegram(
      { headers: { "X-Telegram-Bot-Api-Secret-Token": secret }, body },
      secret,
    );
    expect(result.valid).toBe(true);
    expect(result.eventType).toBe("message");
    expect(result.event?.update_id).toBe(10000);
  });

  it("names other update kinds", async () => {
    const result = await verifyTelegram(
      {
        headers: { "x-telegram-bot-api-secret-token": secret },
        body: JSON.stringify({ update_id: 2, callback_query: { id: "1" } }),
      },
      secret,
    );
    expect(result.eventType).toBe("callback_query");
  });

  it("rejects a wrong token and a missing header", async () => {
    expect(
      (
        await verifyTelegram(
          { headers: { "x-telegram-bot-api-secret-token": "wrong" }, body },
          secret,
        )
      ).code,
    ).toBe("INVALID_SIGNATURE");
    expect((await verifyTelegram({ headers: {}, body }, secret)).code).toBe(
      "MISSING_HEADER",
    );
  });

  it("round-trips signWebhook", async () => {
    const hook = await signWebhook("telegram", {
      secret,
      payload: { update_id: 1 },
    });
    expect((await verifyTelegram(hook, secret)).valid).toBe(true);
  });
});
