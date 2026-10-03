import { describe, expect, expectTypeOf, it, vi } from "vitest";
import { createWebhookHandler as astroHandler } from "../../src/astro.js";
import { createWebhookHandler as remixHandler } from "../../src/remix.js";
import { createWebhookHandler as svelteKitHandler } from "../../src/sveltekit.js";
import type { StripeEvent } from "../../src/index.js";
import {
  dedupeOptions,
  SECRET,
  signStripe,
  tamper,
  webRequest,
} from "./helpers.js";

// SvelteKit, Remix / React Router and Astro all pass `{ request, ... }` to the handler.
const adapters = [
  ["sveltekit", svelteKitHandler],
  ["remix", remixHandler],
  ["astro", astroHandler],
] as const;

describe.each(adapters)("verihook/%s", (_name, createWebhookHandler) => {
  it("verifies and passes the typed event and the framework context", async () => {
    const handler = vi.fn((_payload, result, ctx) => {
      expectTypeOf(result.event).toEqualTypeOf<StripeEvent | undefined>();
      expect(ctx.params).toEqual({ id: "1" });
    });
    const route = createWebhookHandler("stripe", SECRET, handler);
    const signed = await signStripe();

    const res = await route({
      request: webRequest(signed),
      params: { id: "1" },
    });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ received: true });
    const [payload, result] = handler.mock.calls[0];
    expect(payload).toMatchObject({ id: "evt_adapter_1" });
    expect(result.eventType).toBe("invoice.paid");
  });

  it("returns the handler's own Response", async () => {
    const route = createWebhookHandler("stripe", SECRET, () =>
      Response.json({ ok: 1 }, { status: 202 }),
    );
    const res = await route({ request: webRequest(await signStripe()) });
    expect(res.status).toBe(202);
  });

  it("resolves the secret from the context", async () => {
    const route = createWebhookHandler(
      "stripe",
      (ctx: { request: Request; env: { SECRET: string } }) => ctx.env.SECRET,
      () => {},
    );
    const res = await route({
      request: webRequest(await signStripe()),
      env: { SECRET },
    });
    expect(res.status).toBe(200);
  });

  it("rejects a forged signature with 401 without calling the handler", async () => {
    const handler = vi.fn();
    const route = createWebhookHandler("stripe", SECRET, handler);
    const signed = await signStripe();

    const res = await route({
      request: webRequest({ ...signed, headers: tamper(signed.headers) }),
    });

    expect(res.status).toBe(401);
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
    expect((await res.json()).code).toBe("INVALID_SIGNATURE");
    expect(handler).not.toHaveBeenCalled();
  });

  it("uses onError for failures", async () => {
    const route = createWebhookHandler("stripe", SECRET, () => {}, {
      onError: (result) => new Response(result.code, { status: 418 }),
    });
    const res = await route({
      request: webRequest({ ...(await signStripe()), body: "{}" }),
    });
    expect(res.status).toBe(418);
  });

  it("answers 413 above maxBodySize", async () => {
    const route = createWebhookHandler("stripe", SECRET, () => {}, {
      maxBodySize: 10,
    });
    const res = await route({ request: webRequest(await signStripe()) });
    expect(res.status).toBe(413);
  });

  it("acknowledges duplicates with 200 and releases the event when the handler fails", async () => {
    const options = dedupeOptions();
    let fail = true;
    const handler = vi.fn(() => {
      if (fail) throw new Error("db down");
    });
    const route = createWebhookHandler("stripe", SECRET, handler, options);
    const signed = await signStripe("evt_retry");

    expect((await route({ request: webRequest(signed) })).status).toBe(500);
    fail = false;
    expect((await route({ request: webRequest(signed) })).status).toBe(200);
    const dup = await route({ request: webRequest(signed) });
    expect(dup.status).toBe(200);
    expect(await dup.json()).toEqual({ received: true, duplicate: true });
    expect(handler).toHaveBeenCalledTimes(2);
  });
});
