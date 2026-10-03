import { Hono } from "hono";
import { describe, expect, it, vi } from "vitest";
import { verihookHono, type VerihookVariables } from "../../src/hono.js";
import type { StripeEvent } from "../../src/index.js";
import { dedupeOptions, SECRET, signStripe, tamper } from "./helpers.js";

function send(
  app: Hono<any>,
  signed: { headers: Record<string, string>; body: string },
  env?: Record<string, string>,
) {
  return app.request(
    "/webhooks/stripe",
    { method: "POST", headers: signed.headers, body: signed.body },
    env,
  );
}

describe("verihook/hono", () => {
  it("sets c.get('verihook') and leaves the body readable", async () => {
    const app = new Hono<{ Variables: VerihookVariables<StripeEvent> }>();
    app.post("/webhooks/stripe", verihookHono("stripe", SECRET), async (c) => {
      const { event, eventType, payload } = c.get("verihook");
      const body = await c.req.json();
      return c.json({
        id: event?.id,
        eventType,
        same: body.id === (payload as any).id,
      });
    });

    const res = await send(app, await signStripe());

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      id: "evt_adapter_1",
      eventType: "invoice.paid",
      same: true,
    });
  });

  it("resolves the secret from c.env", async () => {
    const app = new Hono<{ Bindings: { STRIPE_SECRET: string } }>();
    app.post(
      "/webhooks/stripe",
      verihookHono("stripe", (c) => c.env.STRIPE_SECRET),
      (c) => c.text("ok"),
    );
    const res = await send(app, await signStripe(), { STRIPE_SECRET: SECRET });
    expect(res.status).toBe(200);
  });

  it("rejects a forged signature with 401", async () => {
    const handler = vi.fn();
    const app = new Hono();
    app.post("/webhooks/stripe", verihookHono("stripe", SECRET), handler);
    const signed = await signStripe();

    const res = await send(app, { ...signed, headers: tamper(signed.headers) });

    expect(res.status).toBe(401);
    expect((await res.json()).code).toBe("INVALID_SIGNATURE");
    expect(handler).not.toHaveBeenCalled();
  });

  it("uses onError and answers 413 above maxBodySize", async () => {
    const app = new Hono();
    app.post(
      "/a",
      verihookHono("stripe", SECRET, {
        onError: (result, c) => c.text(String(result.code), 418),
      }),
      (c) => c.text("ok"),
    );
    app.post("/b", verihookHono("stripe", SECRET, { maxBodySize: 5 }), (c) =>
      c.text("ok"),
    );
    const signed = await signStripe();
    const init = { method: "POST", headers: signed.headers, body: "{}" };

    expect((await app.request("/a", init)).status).toBe(418);
    expect(
      (await app.request("/b", { ...init, body: signed.body })).status,
    ).toBe(413);
  });

  it("returns 500 when the secret resolver throws", async () => {
    const app = new Hono();
    app.post(
      "/webhooks/stripe",
      verihookHono("stripe", () => {
        throw new Error("vault down");
      }),
      (c) => c.text("ok"),
    );
    const res = await send(app, await signStripe());
    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({
      error: "Internal webhook verification error",
    });
  });

  it("releases the event when the route fails, and acks duplicates with 200", async () => {
    let fail = true;
    const app = new Hono();
    app.post(
      "/webhooks/stripe",
      verihookHono("stripe", SECRET, dedupeOptions()),
      (c) => {
        if (fail) throw new Error("db down");
        return c.text("ok");
      },
    );
    const failing = new Hono();
    failing.post(
      "/webhooks/stripe",
      verihookHono("stripe", SECRET, dedupeOptions()),
      (c) => c.text("nope", 503),
    );
    const signed = await signStripe("evt_hono_retry");

    expect((await send(app, signed)).status).toBe(500);
    fail = false;
    expect((await send(app, signed)).status).toBe(200);
    const dup = await send(app, signed);
    expect(dup.status).toBe(200);
    expect(await dup.json()).toEqual({ received: true, duplicate: true });

    expect((await send(failing, signed)).status).toBe(503);
    expect((await send(failing, signed)).status).toBe(503);
  });
});
