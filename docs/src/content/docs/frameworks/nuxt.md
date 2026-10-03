---
title: Nuxt / Nitro / h3
description: Verify webhook signatures in Nuxt server routes, Nitro and h3 with verihook.
sidebar:
  order: 6
---

```ts
// server/api/webhooks/stripe.post.ts
import { createWebhookHandler } from 'verihook/h3';

export default defineEventHandler(
  createWebhookHandler('stripe', process.env.STRIPE_WEBHOOK_SECRET!, async (payload, result, event) => {
    // result.event is a StripeEvent; event is the h3 event
  }),
);
```

Works with h3 v1 (Nuxt 3) and h3 v2. `readBody(event)` still works inside the handler. With `runtimeConfig`, pass a function: `(event) => useRuntimeConfig(event).stripeWebhookSecret`.

`onError(result, event)` returns your own `Response` for failures.

## What the adapter does

| Situation | Response |
| :--- | :--- |
| Invalid, missing or expired signature | `401 { error, code }`, unless you pass `onError` |
| Duplicate event (with `dedupeStore`) | `200 { received: true, duplicate: true }` |
| Body over `maxBodySize` (default 2 MB) | `413 { code: "PAYLOAD_TOO_LARGE" }` |
| Exception during verification | `500` with a generic message |
| Your handler throws or responds `>= 500` | The dedupe key is released so the retry is processed |

All [verification options](../../reference/options/) (`tolerance`, `dedupeStore`, `url`, ...) can be passed as the last argument. Pick your provider in [Providers](../../providers/) for the secret and the headers it sends.
