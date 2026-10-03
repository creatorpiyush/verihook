---
title: Fastify
description: Verify webhook signatures in Fastify with a preHandler hook and a raw-body content parser.
sidebar:
  order: 3
---

Fastify parses JSON before your route runs. Register `verihookRawBody` in the scope of your webhook routes: it keeps `request.rawBody` and still parses JSON and form bodies into `request.body`.

```ts
import Fastify from 'fastify';
import { verihookFastify, verihookRawBody, type VerihookFastifyRequest } from 'verihook/fastify';
import type { StripeEvent } from 'verihook';

const app = Fastify();
await app.register(verihookRawBody);

app.post(
  '/webhooks/stripe',
  { preHandler: verihookFastify('stripe', process.env.STRIPE_WEBHOOK_SECRET!) },
  async (request) => {
    const { event, eventType } = (request as typeof request & VerihookFastifyRequest<StripeEvent>).verihook!;
    return { received: true };
  },
);
```

To keep the raw-body parser away from the rest of your app, register it inside a plugin with only the webhook routes:

```ts
app.register(async (webhooks) => {
  await webhooks.register(verihookRawBody);
  webhooks.post('/webhooks/github', { preHandler: verihookFastify('github', secret) }, handler);
});
```

`onError(result, request, reply)` replaces the default failure reply.

## What the adapter does

| Situation | Response |
| :--- | :--- |
| Invalid, missing or expired signature | `401 { error, code }`, unless you pass `onError` |
| Duplicate event (with `dedupeStore`) | `200 { received: true, duplicate: true }` |
| Body over `maxBodySize` (default 2 MB) | `413 { code: "PAYLOAD_TOO_LARGE" }` |
| Exception during verification | `500` with a generic message |
| Your handler throws or responds `>= 500` | The dedupe key is released so the retry is processed |

All [verification options](../../reference/options/) (`tolerance`, `dedupeStore`, `url`, ...) can be passed as the last argument. Pick your provider in [Providers](../../providers/) for the secret and the headers it sends.
