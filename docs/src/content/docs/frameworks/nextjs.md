---
title: Next.js
description: Verify Stripe, GitHub, Clerk and other webhooks in Next.js App Router route handlers and Pages Router API routes with verihook.
sidebar:
  order: 1
---

## App Router

`createWebhookHandler` returns a route handler. It reads the raw body, verifies it and calls your function only for a valid signature:

```ts
// app/api/webhooks/stripe/route.ts
import { createWebhookHandler } from 'verihook/next';

export const POST = createWebhookHandler('stripe', process.env.STRIPE_WEBHOOK_SECRET!, async (payload, result) => {
  switch (result.eventType) {
    case 'checkout.session.completed':
      // result.event is a StripeEvent
      break;
  }
  // return nothing for 200 { received: true }, or your own Response
});
```

The secret can be a function of the request, e.g. to pick a secret per tenant: `(request) => secretFor(request)`.

To handle failures yourself, pass `onError`:

```ts
export const POST = createWebhookHandler('github', secret, handler, {
  onError: (result) => Response.json({ error: result.code }, { status: 401 }),
});
```

### Without the adapter

Pass the `Request` itself and don't read its body first:

```ts
import { verifyWebhook } from 'verihook';

export async function POST(request: Request) {
  const result = await verifyWebhook('clerk', request, process.env.CLERK_WEBHOOK_SIGNING_SECRET!);
  if (!result.valid) return new Response('Invalid signature', { status: 401 });
  // ...
  return Response.json({ received: true });
}
```

## Pages Router

API routes parse the body by default. Turn that off for the webhook route and read the raw bytes yourself:

```ts
// pages/api/webhooks/stripe.ts
import type { NextApiRequest, NextApiResponse } from 'next';
import { verifyWebhook } from 'verihook';

export const config = { api: { bodyParser: false } };

async function readRawBody(req: NextApiRequest): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks);
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const result = await verifyWebhook(
    'stripe',
    { headers: req.headers, body: await readRawBody(req) },
    process.env.STRIPE_WEBHOOK_SECRET!,
  );
  if (!result.valid) return res.status(401).json({ error: result.code });

  // result.event is a StripeEvent
  res.status(200).json({ received: true });
}
```

## Middleware and edge

If you use `middleware.ts` (Clerk, auth libraries), make the webhook path public so it isn't redirected or blocked. `verihook/next` works on the Edge runtime too.

## What the adapter does

| Situation | Response |
| :--- | :--- |
| Invalid, missing or expired signature | `401 { error, code }`, unless you pass `onError` |
| Duplicate event (with `dedupeStore`) | `200 { received: true, duplicate: true }` |
| Body over `maxBodySize` (default 2 MB) | `413 { code: "PAYLOAD_TOO_LARGE" }` |
| Exception during verification | `500` with a generic message |
| Your handler throws or responds `>= 500` | The dedupe key is released so the retry is processed |

All [verification options](../../reference/options/) (`tolerance`, `dedupeStore`, `url`, ...) can be passed as the last argument. Pick your provider in [Providers](../../providers/) for the secret and the headers it sends.
