---
title: Hono
description: Verify webhook signatures in Hono on Cloudflare Workers, Bun, Deno and Node.js with verihook's middleware.
sidebar:
  order: 4
---

```ts
import { Hono } from 'hono';
import { verihookHono, type VerihookVariables } from 'verihook/hono';
import type { StripeEvent } from 'verihook';

type Env = {
  Bindings: { STRIPE_WEBHOOK_SECRET: string };
  Variables: VerihookVariables<StripeEvent>;
};

const app = new Hono<Env>();

app.post('/webhooks/stripe', verihookHono('stripe', (c) => c.env.STRIPE_WEBHOOK_SECRET), (c) => {
  const { event, eventType } = c.get('verihook');
  return c.json({ received: true });
});

export default app;
```

The secret function receives the context, so it can read Worker bindings. On Node.js or Bun you can pass a string. The body stays readable after verification (`c.req.json()` still works).

`onError(result, c)` returns your own `Response` for failures.

## What the adapter does

| Situation | Response |
| :--- | :--- |
| Invalid, missing or expired signature | `401 { error, code }`, unless you pass `onError` |
| Duplicate event (with `dedupeStore`) | `200 { received: true, duplicate: true }` |
| Body over `maxBodySize` (default 2 MB) | `413 { code: "PAYLOAD_TOO_LARGE" }` |
| Exception during verification | `500` with a generic message |
| Your handler throws or responds `>= 500` | The dedupe key is released so the retry is processed |

All [verification options](../../reference/options/) (`tolerance`, `dedupeStore`, `url`, ...) can be passed as the last argument. Pick your provider in [Providers](../../providers/) for the secret and the headers it sends.
