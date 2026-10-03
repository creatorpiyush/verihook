---
title: NestJS
description: Verify webhook signatures in NestJS with a route guard. Works on the Express and Fastify platforms.
sidebar:
  order: 5
---

Create the app with `rawBody: true` so Nest keeps the raw body:

```ts
// main.ts
const app = await NestFactory.create(AppModule, { rawBody: true });
```

Then guard the webhook route:

```ts
// webhooks.controller.ts
import { Controller, Post, Req, UseGuards } from '@nestjs/common';
import { createVerihookGuard, type VerihookNestRequest } from 'verihook/nestjs';
import type { StripeEvent } from 'verihook';

@Controller('webhooks')
export class WebhooksController {
  @Post('stripe')
  @UseGuards(createVerihookGuard('stripe', process.env.STRIPE_WEBHOOK_SECRET!))
  handle(@Req() req: VerihookNestRequest<StripeEvent>) {
    const { event, eventType } = req.verihook!;
    return { received: true };
  }
}
```

On failure the guard sends the reply itself. To let your exception filters shape it, pass an `exceptionFactory`:

```ts
createVerihookGuard('stripe', secret, {
  exceptionFactory: (result) => new UnauthorizedException(result.reason),
});
```

## What the adapter does

| Situation | Response |
| :--- | :--- |
| Invalid, missing or expired signature | `401 { error, code }`, unless you pass `exceptionFactory` |
| Duplicate event (with `dedupeStore`) | `200 { received: true, duplicate: true }` |
| Body over `maxBodySize` (default 2 MB) | `413 { code: "PAYLOAD_TOO_LARGE" }` |
| Exception during verification | `500` with a generic message |
| Your handler throws or responds `>= 500` | The dedupe key is released so the retry is processed |

All [verification options](../../reference/options/) (`tolerance`, `dedupeStore`, `url`, ...) can be passed as the last argument. Pick your provider in [Providers](../../providers/) for the secret and the headers it sends.
