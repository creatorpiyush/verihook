import { describe, expect, it, vi } from "vitest";
import {
  MemoryDedupeStore,
  registerProvider,
  verifyWebhook,
  verifyWebhookOrThrow,
} from "../src/index.js";
import { verihookExpress } from "../src/express.js";
import { createWebhookHandler } from "../src/next.js";
import { createSignedRequest, signWebhook } from "../src/testing/sign.js";

const svixSecret = "whsec_dGVzdF9zZWNyZXRfa2V5X2Zvcl9zdml4XzEyMw==";

async function verifySigned(
  provider: string,
  options: Parameters<typeof signWebhook>[1],
) {
  const hook = await signWebhook(provider, options);
  return verifyWebhook(
    provider,
    { headers: hook.headers, body: hook.body, url: hook.url },
    hook.secret,
  );
}

describe("result.event and result.eventType", () => {
  it.each([
    [
      "stripe",
      { secret: "whsec_x", payload: { type: "invoice.paid" } },
      "invoice.paid",
    ],
    [
      "svix",
      { secret: svixSecret, payload: { type: "user.created" } },
      "user.created",
    ],
    [
      "clerk",
      { secret: svixSecret, payload: { type: "session.ended" } },
      "session.ended",
    ],
    ["github", { secret: "gh", event: "push" }, "push"],
    ["shopify", { secret: "s", event: "products/update" }, "products/update"],
    [
      "slack",
      { secret: "s", payload: { type: "event_callback" } },
      "event_callback",
    ],
    [
      "linear",
      { secret: "s", payload: { type: "Issue", action: "create" } },
      "Issue",
    ],
    [
      "razorpay",
      { secret: "s", payload: { event: "payment.captured" } },
      "payment.captured",
    ],
    [
      "square",
      { secret: "s", payload: { type: "payment.created" } },
      "payment.created",
    ],
    [
      "zoom",
      { secret: "s", payload: { event: "meeting.started" } },
      "meeting.started",
    ],
    [
      "whatsapp",
      {
        secret: "s",
        payload: { object: "whatsapp_business_account", entry: [] },
      },
      "whatsapp_business_account",
    ],
    [
      "twitter",
      { secret: "s", payload: { for_user_id: "1", tweet_create_events: [] } },
      "tweet_create_events",
    ],
    [
      "lemonsqueezy",
      { secret: "s", payload: { meta: { event_name: "order_created" } } },
      "order_created",
    ],
    [
      "paddle",
      { secret: "s", payload: { event_type: "transaction.completed" } },
      "transaction.completed",
    ],
    [
      "pagerduty",
      { secret: "s", payload: { event: { event_type: "incident.triggered" } } },
      "incident.triggered",
    ],
    [
      "webflow",
      { secret: "s", payload: { triggerType: "form_submission" } },
      "form_submission",
    ],
    [
      "workos",
      { secret: "s", payload: { event: "dsync.user.created" } },
      "dsync.user.created",
    ],
    ["discord", { payload: { type: 1, application_id: "1" } }, "PING"],
    [
      "discord",
      { payload: { type: 1, event: { type: "APPLICATION_AUTHORIZED" } } },
      "APPLICATION_AUTHORIZED",
    ],
    [
      "generic",
      { secret: "s", payload: { event_type: "thing.done" } },
      "thing.done",
    ],
  ] as const)("%s → %s", async (provider, options, eventType) => {
    const result = await verifySigned(provider, options);
    expect(result.valid).toBe(true);
    expect(result.eventType).toBe(eventType);
    expect(result.event).toBeTypeOf("object");
  });

  it("parses form posts into fields", async () => {
    const result = await verifySigned("twilio", {
      secret: "tw",
      form: { MessageSid: "SM1", Body: "Hi" },
    });
    expect(result.event).toEqual({ MessageSid: "SM1", Body: "Hi" });
    expect(result.eventType).toBeUndefined();
  });

  it("reads Slack slash commands and interactivity payloads", async () => {
    const command = await verifySigned("slack", {
      secret: "s",
      form: { command: "/deploy", text: "prod" },
    });
    expect(command.eventType).toBe("/deploy");

    const interaction = await verifySigned("slack", {
      secret: "s",
      form: { payload: JSON.stringify({ type: "block_actions" }) },
    });
    expect(interaction.eventType).toBe("block_actions");

    const broken = await verifySigned("slack", {
      secret: "s",
      form: { payload: "{not json" },
    });
    expect(broken.valid).toBe(true);
    expect(broken.eventType).toBeUndefined();
  });

  it("leaves event undefined for bodies that are not JSON or form", async () => {
    const result = await verifySigned("github", {
      secret: "gh",
      payload: "plain text",
    });
    expect(result.valid).toBe(true);
    expect(result.event).toBeUndefined();
    expect(result.eventType).toBe("ping");
  });

  it("never exposes the payload of a failed verification", async () => {
    const hook = await signWebhook("stripe", {
      secret: "whsec_a",
      payload: { type: "invoice.paid" },
    });
    const result = await verifyWebhook(
      "stripe",
      { headers: hook.headers, body: hook.body },
      "whsec_b",
    );
    expect(result.valid).toBe(false);
    expect(result.event).toBeUndefined();
    expect(result.eventType).toBeUndefined();
  });

  it("drops the event of a duplicate and keeps it with the dedupe key", async () => {
    const dedupeStore = new MemoryDedupeStore();
    const hook = await signWebhook("stripe", {
      secret: "whsec_a",
      payload: { id: "evt_1", type: "invoice.paid" },
    });
    const req = { headers: hook.headers, body: hook.body };
    const first = await verifyWebhook("stripe", req, "whsec_a", {
      dedupeStore,
    });
    expect(first.dedupeKey).toBe("stripe:evt_1");
    expect(first.eventType).toBe("invoice.paid");
    const second = await verifyWebhook("stripe", req, "whsec_a", {
      dedupeStore,
    });
    expect(second.code).toBe("DUPLICATE_EVENT");
    expect(second.event).toBeUndefined();
  });

  it("reports eventType to telemetry and returns it from verifyWebhookOrThrow", async () => {
    const onVerify = vi.fn();
    const hook = await signWebhook("github", { secret: "gh", event: "issues" });
    const result = await verifyWebhookOrThrow(
      "github",
      { headers: hook.headers, body: hook.body },
      "gh",
      { onVerify },
    );
    expect(result.eventType).toBe("issues");
    expect(onVerify.mock.calls[0][0].eventType).toBe("issues");
    expect(onVerify.mock.calls[0][0]).not.toHaveProperty("event");
  });

  it("uses a custom provider's eventType, falling back to common fields", async () => {
    const hook = await signWebhook("generic", {
      secret: "s",
      payload: { kind: "custom.kind", type: "ignored" },
    });
    const genericVerify = async () => ({ valid: true, provider: "acme" });

    registerProvider({
      name: "acme-typed",
      verify: genericVerify,
      eventType: (event) => (event as { kind: string }).kind,
    });
    registerProvider({ name: "acme-default", verify: genericVerify });
    registerProvider({
      name: "acme-throws",
      verify: genericVerify,
      eventType: () => {
        throw new Error("boom");
      },
    });

    const req = { headers: hook.headers, body: hook.body };
    expect((await verifyWebhook("acme-typed", req, "s")).eventType).toBe(
      "custom.kind",
    );
    expect((await verifyWebhook("acme-default", req, "s")).eventType).toBe(
      "ignored",
    );
    const thrown = await verifyWebhook("acme-throws", req, "s");
    expect(thrown.valid).toBe(true);
    expect(thrown.eventType).toBeUndefined();
  });
});

describe("framework adapters expose the event", () => {
  it("passes result.event to the Next.js handler", async () => {
    const seen = vi.fn();
    const handler = createWebhookHandler("stripe", "whsec_a", (_p, result) => {
      seen(result.event?.type, result.eventType);
    });
    const req = await createSignedRequest("stripe", {
      secret: "whsec_a",
      payload: { type: "invoice.paid" },
    });
    const res = await handler(req);
    expect(res.status).toBe(200);
    expect(seen).toHaveBeenCalledWith("invoice.paid", "invoice.paid");
  });

  it("adds event and eventType to req.verihook in Express", async () => {
    const hook = await signWebhook("github", {
      secret: "gh",
      event: "push",
      payload: { ref: "refs/heads/main" },
    });
    const req: Record<string, unknown> = {
      headers: hook.headers,
      body: hook.body,
    };
    const next = vi.fn();
    const res = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn().mockReturnThis(),
      setHeader: vi.fn().mockReturnThis(),
    };
    await verihookExpress("github", "gh")(req, res, next);
    expect(next).toHaveBeenCalledWith();
    const verihook = req.verihook as { event: unknown; eventType: string };
    expect(verihook.event).toEqual({ ref: "refs/heads/main" });
    expect(verihook.eventType).toBe("push");
  });
});
