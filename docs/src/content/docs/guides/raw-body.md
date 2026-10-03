---
title: Why the raw body matters
description: Webhook signatures cover the exact bytes sent. How to keep the raw request body in Express, Next.js, Fastify, NestJS, Hono, Nuxt, SvelteKit and AWS Lambda.
sidebar:
  order: 1
---

Providers sign the **exact bytes** of the request body. To check the signature, verihook recomputes it over the same bytes. If anything changes them first, the signature no longer matches and you get `INVALID_SIGNATURE`, even with the right secret.

The usual culprit is a JSON body parser. `JSON.stringify(JSON.parse(body))` is not the original body: whitespace, key order, escaped characters (`é` vs `é`) and number formatting can all change.

When the parsed body's size doesn't match `content-length`, verihook's `result.hint` tells you the body was modified.

## Framework by framework

| Framework | What to do |
| :--- | :--- |
| Next.js App Router | Use `verihook/next`, or pass the `Request` itself. Don't call `request.json()` before verifying. |
| Next.js Pages Router | Disable the body parser for the route (`export const config = { api: { bodyParser: false } }`) and read the raw body. See [Next.js](../../frameworks/nextjs/#pages-router). |
| Express | Use `verihookExpress` on the webhook route **before** `express.json()`, or mount `express.raw({ type: '*/*' })` on that route. |
| Fastify | Register `verihookRawBody` in the scope of your webhook routes. |
| NestJS | Create the app with `NestFactory.create(AppModule, { rawBody: true })`. |
| Hono, Workers, Deno, Bun | Pass the `Request` or use `verihookHono`. The body stays readable after verification. |
| Nuxt / h3, SvelteKit, Remix, Astro | Use the adapter (`verihook/h3`, ...). It reads the raw body first. |
| AWS Lambda | Use `verihook/lambda`. It decodes base64 bodies from API Gateway and Function URLs. |

## Verifying by hand

If you can't use an adapter, read the body as text once and use that string for both verification and parsing:

```ts
const rawBody = await request.text();

const result = await verifyWebhook('stripe', { headers: request.headers, body: rawBody }, secret);
if (!result.valid) return new Response('Invalid signature', { status: 401 });

const event = JSON.parse(rawBody); // or use result.event, which is already parsed
```

With Express and a raw parser:

```ts
app.post('/webhooks/stripe', express.raw({ type: '*/*' }), async (req, res) => {
  const result = await verifyWebhook('stripe', { headers: req.headers, body: req.body }, secret);
  // req.body is a Buffer with the original bytes
});
```

## Other things that change the body

- Middleware that decompresses, trims or re-encodes bodies.
- Proxies or API gateways that transform payloads (mapping templates, request rewriting).
- Logging middleware that consumes the request stream. The hint reports an empty body with a non-zero `content-length`.
