import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import {
  createApp,
  createRouter,
  defineEventHandler,
  readRawBody,
  toNodeListener,
} from "h3";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { createWebhookHandler } from "../../src/h3.js";
import {
  dedupeOptions,
  SECRET,
  signStripe,
  tamper,
  webRequest,
} from "./helpers.js";

describe("verihook/h3 with h3 v1 (Nuxt 3)", () => {
  let server: Server;
  let base: string;
  let fail = false;
  const handler = vi.fn(async (_payload, result, event) => {
    if (fail) throw new Error("db down");
    // The body is still readable by h3 after verification.
    const raw = await readRawBody(event);
    return Response.json({
      eventType: result.eventType,
      rawLength: raw?.length,
    });
  });

  beforeAll(async () => {
    const app = createApp();
    const router = createRouter()
      .post(
        "/webhooks/stripe",
        defineEventHandler(
          createWebhookHandler("stripe", SECRET, handler, dedupeOptions()),
        ),
      )
      .post(
        "/small",
        defineEventHandler(
          createWebhookHandler("stripe", SECRET, () => {}, { maxBodySize: 5 }),
        ),
      )
      .post(
        "/env",
        defineEventHandler(
          createWebhookHandler(
            "stripe",
            (event: any) => event.context.secret,
            () => {},
          ),
        ),
      );
    app.use(
      defineEventHandler((event) => void (event.context.secret = SECRET)),
    );
    app.use(router);
    server = createServer(toNodeListener(app));
    await new Promise<void>((resolve) => server.listen(0, resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterAll(() => {
    server.closeAllConnections();
    return new Promise<void>((resolve) => server.close(() => resolve()));
  });

  const post = (
    path: string,
    signed: { headers: Record<string, string>; body: string },
  ) =>
    fetch(base + path, {
      method: "POST",
      headers: signed.headers,
      body: signed.body,
    });

  it("verifies the Node.js request and returns the handler's Response", async () => {
    const signed = await signStripe("evt_h3_1");
    const res = await post("/webhooks/stripe", signed);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      eventType: "invoice.paid",
      rawLength: signed.body.length,
    });
  });

  it("rejects forged signatures, oversized bodies, and resolves the secret from the event", async () => {
    const signed = await signStripe("evt_h3_2");
    expect(
      (
        await post("/webhooks/stripe", {
          ...signed,
          headers: tamper(signed.headers),
        })
      ).status,
    ).toBe(401);
    expect((await post("/small", signed)).status).toBe(413);
    expect((await post("/env", signed)).status).toBe(200);
  });

  it("releases the event when the handler fails", async () => {
    const signed = await signStripe("evt_h3_retry");
    fail = true;
    expect((await post("/webhooks/stripe", signed)).status).toBe(500);
    fail = false;
    expect((await post("/webhooks/stripe", signed)).status).toBe(200);
    const dup = await post("/webhooks/stripe", signed);
    expect(await dup.json()).toEqual({ received: true, duplicate: true });
  });
});

describe("verihook/h3 event shapes", () => {
  it("uses event.req on h3 v2", async () => {
    const route = createWebhookHandler("stripe", SECRET, () => {});
    const res = await route({ req: webRequest(await signStripe()) });
    expect(res.status).toBe(200);
  });

  it("uses an already-buffered node body (serverless presets)", async () => {
    const signed = await signStripe();
    const route = createWebhookHandler("stripe", SECRET, () => {});
    const nodeReq = Object.assign((async function* () {})(), {
      headers: { ...signed.headers, host: "example.com" },
      method: "POST",
      url: "/webhooks/stripe",
      body: Buffer.from(signed.body),
    });
    const res = await route({ node: { req: nodeReq } });
    expect(res.status).toBe(200);
  });

  it("fails with 500 when the event has no request", async () => {
    const route = createWebhookHandler("stripe", SECRET, () => {});
    expect((await route({})).status).toBe(500);
  });
});
