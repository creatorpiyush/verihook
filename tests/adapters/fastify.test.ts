import Fastify from "fastify";
import { describe, expect, it, vi } from "vitest";
import {
  verihookFastify,
  verihookRawBody,
  type VerihookFastifyRequest,
} from "../../src/fastify.js";
import { signWebhook } from "../../src/testing.js";
import type { StripeEvent } from "../../src/index.js";
import { dedupeOptions, SECRET, signStripe, tamper } from "./helpers.js";

function inject(
  app: ReturnType<typeof Fastify>,
  signed: { headers: Record<string, string>; body: string },
  url = "/webhooks/stripe",
) {
  return app.inject({
    method: "POST",
    url,
    headers: signed.headers,
    payload: signed.body,
  });
}

describe("verihook/fastify", () => {
  it("verifies with verihookRawBody and keeps request.body parsed", async () => {
    const app = Fastify();
    await app.register(verihookRawBody);
    app.post(
      "/webhooks/stripe",
      { preHandler: verihookFastify("stripe", SECRET) },
      async (request) => {
        const { event, eventType } = (
          request as VerihookFastifyRequest<StripeEvent>
        ).verihook!;
        return { id: event?.id, eventType, bodyId: (request.body as any).id };
      },
    );

    const res = await inject(app, await signStripe());

    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({
      id: "evt_adapter_1",
      eventType: "invoice.paid",
      bodyId: "evt_adapter_1",
    });
  });

  it("verifies form-encoded webhooks (Slack) and parses the fields", async () => {
    const app = Fastify();
    await app.register(verihookRawBody);
    app.post(
      "/webhooks/slack",
      { preHandler: verihookFastify("slack", "slack_secret") },
      async (request) => request.body,
    );
    const signed = await signWebhook("slack", {
      secret: "slack_secret",
      form: { command: "/deploy", text: "prod" },
    });

    const res = await inject(app, signed, "/webhooks/slack");

    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ command: "/deploy", text: "prod" });
  });

  it("accepts a string body from a user-defined parseAs parser", async () => {
    const app = Fastify();
    app.addContentTypeParser(
      "application/json",
      { parseAs: "string" },
      (_r, body, done) => done(null, body),
    );
    app.post(
      "/webhooks/stripe",
      { preHandler: verihookFastify("stripe", () => SECRET) },
      async (request) => (request as VerihookFastifyRequest).verihook!.payload,
    );
    const res = await inject(app, await signStripe());
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ id: "evt_adapter_1" });
  });

  it("rejects a body already parsed by Fastify's default JSON parser", async () => {
    const handler = vi.fn();
    const app = Fastify();
    app.post(
      "/webhooks/stripe",
      { preHandler: verihookFastify("stripe", SECRET) },
      handler,
    );
    const res = await inject(app, await signStripe());
    expect(res.statusCode).toBe(401);
    expect(handler).not.toHaveBeenCalled();
  });

  it("rejects forged signatures, oversized bodies, and supports onError", async () => {
    const app = Fastify();
    await app.register(verihookRawBody);
    app.post(
      "/webhooks/stripe",
      { preHandler: verihookFastify("stripe", SECRET) },
      async () => "ok",
    );
    app.post(
      "/small",
      { preHandler: verihookFastify("stripe", SECRET, { maxBodySize: 5 }) },
      async () => "ok",
    );
    app.post(
      "/custom",
      {
        preHandler: verihookFastify("stripe", SECRET, {
          onError: (result, _req, reply) =>
            reply.code(418).send({ code: result.code }),
        }),
      },
      async () => "ok",
    );
    const signed = await signStripe();
    const forged = { ...signed, headers: tamper(signed.headers) };

    const res = await inject(app, forged);
    expect(res.statusCode).toBe(401);
    expect(res.headers["x-content-type-options"]).toBe("nosniff");
    expect(res.json().code).toBe("INVALID_SIGNATURE");
    expect((await inject(app, signed, "/small")).statusCode).toBe(413);
    expect((await inject(app, forged, "/custom")).statusCode).toBe(418);
  });

  it("returns 500 when the secret resolver throws", async () => {
    const app = Fastify();
    await app.register(verihookRawBody);
    const preHandler = verihookFastify("stripe", () => {
      throw new Error("vault down");
    });
    app.post("/webhooks/stripe", { preHandler }, async () => "ok");
    const res = await inject(app, await signStripe());
    expect(res.statusCode).toBe(500);
    expect(res.json()).toEqual({
      error: "Internal webhook verification error",
    });
  });

  it("answers 400 for invalid JSON", async () => {
    const app = Fastify();
    await app.register(verihookRawBody);
    app.post(
      "/webhooks/stripe",
      { preHandler: verihookFastify("stripe", SECRET) },
      async () => "ok",
    );
    const signed = await signStripe();
    expect((await inject(app, { ...signed, body: "{nope" })).statusCode).toBe(
      400,
    );
  });

  it("releases the event when the route fails, and acks duplicates with 200", async () => {
    let fail = true;
    const app = Fastify();
    await app.register(verihookRawBody);
    app.post(
      "/webhooks/stripe",
      { preHandler: verihookFastify("stripe", SECRET, dedupeOptions()) },
      async () => {
        if (fail) throw new Error("db down");
        return "ok";
      },
    );
    const signed = await signStripe("evt_fastify_retry");

    expect((await inject(app, signed)).statusCode).toBe(500);
    // The release runs on the response's "finish" event, which inject() doesn't wait for.
    await new Promise((resolve) => setImmediate(resolve));
    fail = false;
    expect((await inject(app, signed)).statusCode).toBe(200);
    const dup = await inject(app, signed);
    expect(dup.statusCode).toBe(200);
    expect(dup.json()).toEqual({ received: true, duplicate: true });
  });
});
