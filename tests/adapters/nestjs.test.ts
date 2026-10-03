import "reflect-metadata";
import type { AddressInfo } from "node:net";
import {
  Controller,
  Module,
  Post,
  Req,
  UnauthorizedException,
  UseGuards,
  type INestApplication,
} from "@nestjs/common";
import { NestFactory } from "@nestjs/core";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import {
  createVerihookGuard,
  type VerihookNestRequest,
} from "../../src/nestjs.js";
import { dedupeOptions, SECRET, signStripe, tamper } from "./helpers.js";

let fail = false;

class WebhookController {
  stripe(req: VerihookNestRequest & { body: { id: string } }) {
    if (fail) throw new Error("db down");
    const { eventType, payload } = req.verihook!;
    return { eventType, payloadId: (payload as any).id, bodyId: req.body.id };
  }
  custom() {
    return { ok: true };
  }
  small() {
    return { ok: true };
  }
}

// Decorators applied by hand so the test doesn't need `experimentalDecorators`.
function route(
  method: keyof WebhookController,
  path: string,
  guard: ReturnType<typeof createVerihookGuard>,
) {
  const descriptor = Object.getOwnPropertyDescriptor(
    WebhookController.prototype,
    method,
  )!;
  Req()(WebhookController.prototype, method, 0);
  Post(path)(WebhookController.prototype, method, descriptor);
  UseGuards(guard)(WebhookController.prototype, method, descriptor);
}
route(
  "stripe",
  "stripe",
  createVerihookGuard("stripe", SECRET, dedupeOptions()),
);
route(
  "custom",
  "custom",
  createVerihookGuard("stripe", () => SECRET, {
    exceptionFactory: (result) => new UnauthorizedException(result.code),
  }),
);
route(
  "small",
  "small",
  createVerihookGuard("stripe", SECRET, { maxBodySize: 5 }),
);
Controller("webhooks")(WebhookController);

class AppModule {}
Module({ controllers: [WebhookController] })(AppModule);

describe("verihook/nestjs (Express platform)", () => {
  let app: INestApplication;
  let base: string;

  beforeAll(async () => {
    app = await NestFactory.create(AppModule, { rawBody: true, logger: false });
    await app.listen(0);
    base = `http://127.0.0.1:${(app.getHttpServer().address() as AddressInfo).port}`;
  });
  afterAll(() => app.close());

  const post = (
    path: string,
    signed: { headers: Record<string, string>; body: string },
  ) =>
    fetch(`${base}/webhooks/${path}`, {
      method: "POST",
      headers: signed.headers,
      body: signed.body,
    });

  it("verifies with Nest's rawBody and sets req.verihook", async () => {
    const res = await post("stripe", await signStripe("evt_nest_1"));
    expect(res.status).toBe(201);
    expect(await res.json()).toEqual({
      eventType: "invoice.paid",
      payloadId: "evt_nest_1",
      bodyId: "evt_nest_1",
    });
  });

  it("replies 401 to a forged signature without a 403 on top", async () => {
    const signed = await signStripe("evt_nest_2");
    const res = await post("stripe", {
      ...signed,
      headers: tamper(signed.headers),
    });
    expect(res.status).toBe(401);
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
    expect((await res.json()).code).toBe("INVALID_SIGNATURE");
  });

  it("throws the exceptionFactory's exception, and answers 413 above maxBodySize", async () => {
    const signed = await signStripe("evt_nest_3");
    const res = await post("custom", {
      ...signed,
      headers: tamper(signed.headers),
    });
    expect(res.status).toBe(401);
    expect((await res.json()).message).toBe("INVALID_SIGNATURE");
    expect((await post("small", signed)).status).toBe(413);
  });

  it("releases the event when the route fails, and acks duplicates with 200", async () => {
    const signed = await signStripe("evt_nest_retry");
    fail = true;
    expect((await post("stripe", signed)).status).toBe(500);
    fail = false;
    expect((await post("stripe", signed)).status).toBe(201);
    const dup = await post("stripe", signed);
    expect(dup.status).toBe(200);
    expect(await dup.json()).toEqual({ received: true, duplicate: true });
  });
});

describe("createVerihookGuard with a Fastify reply", () => {
  function context(req: object, reply: object) {
    return {
      switchToHttp: () => ({
        getRequest: <T>() => req as T,
        getResponse: <T>() => reply as T,
      }),
    };
  }

  it("replies through reply.code().headers().send() and releases on 5xx", async () => {
    const signed = await signStripe("evt_nest_fastify");
    const listeners: Array<() => void> = [];
    const reply: any = {
      code: vi.fn(() => reply),
      headers: vi.fn(() => reply),
      send: vi.fn(() => reply),
      raw: {
        statusCode: 500,
        on: (_e: string, cb: () => void) => listeners.push(cb),
      },
    };
    const options = dedupeOptions();
    const guard = createVerihookGuard("stripe", SECRET, options);
    const req = () => ({
      headers: signed.headers,
      rawBody: Buffer.from(signed.body),
      body: JSON.parse(signed.body),
      url: "/webhooks/stripe",
      method: "POST",
    });

    expect(await guard.canActivate(context(req(), reply))).toBe(true);
    listeners[0]();
    await new Promise((resolve) => setImmediate(resolve));
    // Released, so the retry passes again.
    expect(await guard.canActivate(context(req(), reply))).toBe(true);
    expect(await guard.canActivate(context(req(), reply))).toBe(false);
    expect(reply.code).toHaveBeenCalledWith(200);

    const bad = { ...req(), headers: tamper(signed.headers) };
    expect(await guard.canActivate(context(bad, reply))).toBe(false);
    expect(reply.code).toHaveBeenCalledWith(401);
  });

  it("answers 500 when the secret resolver throws, and errors on unknown responses", async () => {
    const guard = createVerihookGuard("stripe", () => {
      throw new Error("vault down");
    });
    const res: any = { status: vi.fn(() => res), json: vi.fn(() => res) };
    expect(await guard.canActivate(context({ headers: {} }, res))).toBe(false);
    expect(res.status).toHaveBeenCalledWith(500);
    await expect(
      guard.canActivate(context({ headers: {} }, {})),
    ).rejects.toThrow("Unsupported Nest HTTP adapter response");
  });
});
