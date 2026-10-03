---
title: Edge runtimes and bundle size
description: Run verihook on Cloudflare Workers, Vercel Edge, Deno and Bun, and import a single provider to keep edge bundles small.
sidebar:
  order: 7
---

verihook uses the Web Crypto API (`crypto.subtle`) and has no dependencies, so it runs on Cloudflare Workers, Vercel Edge, Deno, Bun and Node.js 18.17+ without polyfills.

## Import one provider

Every provider has its own subpath. A bundler then includes only that provider:

```ts
import { verifyStripe } from 'verihook/stripe';
import { verifyResend } from 'verihook/svix';                  // Svix, Resend and Clerk
import { verifyWhatsApp, verifyMetaChallenge } from 'verihook/meta';
```

| Import | Size (min + brotli) |
| :--- | :--- |
| `verifyWebhook` from `verihook` (all providers) | ~10 kB |
| `verifyStripe` from `verihook/stripe` | ~4 kB |

Each subpath exports the provider's `verify*` functions, its verifier, its event type and `WebhookErrorCode`. Results, hints, dedupe and telemetry are the same as `verifyWebhook`. A subpath always uses the built-in verifier, so `registerProvider()` overrides apply only to `verifyWebhook`.

## Cloudflare Workers

Secrets live in bindings, so pass a function that reads them per request:

```ts
import { Hono } from 'hono';
import { verihookHono } from 'verihook/hono';

const app = new Hono<{ Bindings: { STRIPE_WEBHOOK_SECRET: string } }>();
app.post('/webhooks/stripe', verihookHono('stripe', (c) => c.env.STRIPE_WEBHOOK_SECRET), (c) =>
  c.json({ received: true }),
);
export default app;
```

`MemoryDedupeStore` is per isolate. Use [a shared store](../dedupe/#shared-stores) such as Workers KV.

## Deno

Install from JSR (`deno add jsr:@verihook/verihook`) or npm (`deno add npm:verihook`). verihook needs no permissions. It reads `NODE_ENV` only when env access is already granted, so it never triggers a permission prompt.

```ts
import { verifyGitHub } from '@verihook/verihook/github';

Deno.serve(async (request) => {
  const result = await verifyGitHub(request, Deno.env.get('GITHUB_WEBHOOK_SECRET')!);
  return result.valid ? Response.json({ received: true }) : new Response('Invalid signature', { status: 401 });
});
```
