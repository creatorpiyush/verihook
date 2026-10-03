// Compile-time checks that the adapters plug into the real framework types
// without casts (run by `npm run typecheck`).
import { UseGuards } from "@nestjs/common";
import Fastify from "fastify";
import { defineEventHandler } from "h3";
import { Hono } from "hono";
import { expectTypeOf } from "vitest";
import type { GitHubEvent, StripeEvent } from "../../src/index.js";
import {
  verihookFastify,
  verihookRawBody,
  type VerihookFastifyRequest,
} from "../../src/fastify.js";
import { createWebhookHandler as h3Handler } from "../../src/h3.js";
import { verihookHono, type VerihookVariables } from "../../src/hono.js";
import { createWebhookHandler as lambdaHandler } from "../../src/lambda.js";
import { createVerihookGuard } from "../../src/nestjs.js";
import { createWebhookHandler as svelteKitHandler } from "../../src/sveltekit.js";

interface MyEvent {
  kind: "custom";
}

export function honoChecks() {
  const app = new Hono<{
    Bindings: { SECRET: string };
    Variables: VerihookVariables<StripeEvent>;
  }>();
  app.post(
    "/webhooks/stripe",
    verihookHono("stripe", (c) => c.env.SECRET),
    (c) => {
      expectTypeOf(c.get("verihook").event).toEqualTypeOf<
        StripeEvent | undefined
      >();
      return c.text("ok");
    },
  );
}

export async function fastifyChecks() {
  const app = Fastify();
  await app.register(verihookRawBody);
  app.post(
    "/webhooks/github",
    { preHandler: verihookFastify("github", (req) => String(req.headers.x)) },
    async (request) => {
      const { verihook } = request as typeof request &
        VerihookFastifyRequest<GitHubEvent>;
      expectTypeOf(verihook!.event).toEqualTypeOf<GitHubEvent | undefined>();
    },
  );
}

export function h3Checks() {
  return defineEventHandler(
    h3Handler("stripe", "s", (_payload, result) => {
      expectTypeOf(result.event).toEqualTypeOf<StripeEvent | undefined>();
    }),
  );
}

export function svelteKitChecks() {
  svelteKitHandler<MyEvent>("generic", "s", (_payload, result) => {
    expectTypeOf(result.event).toEqualTypeOf<MyEvent | undefined>();
  });
}

export function lambdaChecks() {
  lambdaHandler("stripe", "s", (_payload, result) => {
    expectTypeOf(result.event).toEqualTypeOf<StripeEvent | undefined>();
    return { statusCode: 204 };
  });
}

export function nestChecks() {
  UseGuards(createVerihookGuard("stripe", "s"));
}
