---
title: Express
description: Verify webhook signatures in Express with one middleware. Keeps the raw body, works alongside express.json().
sidebar:
  order: 2
---

```ts
import express from 'express';
import { verihookExpress, type VerihookRequestAdditions } from 'verihook/express';
import type { StripeEvent } from 'verihook';

const app = express();

app.post('/webhooks/stripe', verihookExpress('stripe', process.env.STRIPE_WEBHOOK_SECRET!), (req, res) => {
  // req.verihook is set only when the signature is valid
  const { event, eventType } = (req as typeof req & VerihookRequestAdditions<StripeEvent>).verihook!;
  res.json({ received: true });
});

// Other routes can use the JSON parser
app.use(express.json());
```

## The body parser

`verihookExpress` reads the request stream itself. That only works if no parser consumed it first, so either:

- register the webhook route **before** `app.use(express.json())`, or
- mount `express.raw({ type: '*/*' })` on the webhook route; the middleware accepts the Buffer it produces.

If a JSON parser ran first, verification fails and `result.hint` says the body was parsed.

## Options

```ts
verihookExpress('github', (req) => secretFor(req), {
  maxBodySize: 1024 * 1024,
  dedupeStore,
  onError: (result, req, res) => res.status(401).json({ error: result.code }),
});
```

`onError` replaces the default failure response.

## What the adapter does

| Situation | Response |
| :--- | :--- |
| Invalid, missing or expired signature | `401 { error, code }`, unless you pass `onError` |
| Duplicate event (with `dedupeStore`) | `200 { received: true, duplicate: true }` |
| Body over `maxBodySize` (default 2 MB) | `413 { code: "PAYLOAD_TOO_LARGE" }` |
| Exception during verification | `500` with a generic message |
| Your handler throws or responds `>= 500` | The dedupe key is released so the retry is processed |

All [verification options](../../reference/options/) (`tolerance`, `dedupeStore`, `url`, ...) can be passed as the last argument. Pick your provider in [Providers](../../providers/) for the secret and the headers it sends.
