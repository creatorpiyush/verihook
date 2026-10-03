# verihook 🪝

> **Universal, typed webhook signature verifier** for TypeScript and JavaScript.

[![npm version](https://img.shields.io/npm/v/verihook.svg)](https://www.npmjs.com/package/verihook)
[![license](https://img.shields.io/npm/l/verihook.svg)](https://github.com/creatorpiyush/verihook/blob/main/LICENSE)
[![CI Verification](https://github.com/creatorpiyush/verihook/actions/workflows/pr-verify.yml/badge.svg)](https://github.com/creatorpiyush/verihook/actions)
[![code coverage](https://img.shields.io/badge/coverage-96%25-brightgreen.svg)](https://github.com/creatorpiyush/verihook)
[![zero dependencies](https://img.shields.io/badge/dependencies-0-success.svg)](https://www.npmjs.com/package/verihook)
[![TypeScript](https://img.shields.io/badge/TypeScript-Strict-blue.svg)](https://www.typescriptlang.org/)
[![npm downloads](https://img.shields.io/npm/dm/verihook.svg)](https://www.npmjs.com/package/verihook)

`verihook` provides a unified, strongly-typed API for verifying webhook signatures across popular services (**Stripe, GitHub, Shopify, Slack, Twilio, Svix/Resend/Clerk, Meta/WhatsApp, Discord, Twitter/X, PayPal, LemonSqueezy, Paddle, PagerDuty, Webflow, WorkOS, Linear, Razorpay, Square, Zoom, and custom webhooks**).

No more hunting down bespoke HMAC code snippets for every service or installing 10 heavy SDK dependencies just to verify incoming webhooks!

📖 Read the full [Architecture & Technical Specification](./ARCHITECTURE.md) and [Security Policy](./SECURITY.md).

---

## Features

- ⚡ **Zero Runtime Dependencies**: Powered by standard Web Crypto API (`crypto.subtle`) with Node.js fallback.
- 🚀 **1-Line Framework Adapters**: Express, Next.js, Fastify, Hono, NestJS, Nuxt/h3, SvelteKit, Remix/React Router, Astro and AWS Lambda, each a subpath import (`verihook/fastify`, ...). They share the same raw-body handling, size limits and duplicate/retry semantics.
- 🛡️ **Hardened & Secure**: Built-in SSRF origin protection, unparsed payload stream byte limits (`maxBodySize`), and standard HTTP security headers (`nosniff`, `DENY`).
- 🌐 **Edge Ready**: Runs anywhere — Node.js, Vercel Edge, Cloudflare Workers, Deno, Bun, Next.js, Hono, Express, Fastify.
- 🔐 **Timing-Safe**: Protects against side-channel timing attacks out of the box.
- ⏳ **Replay Attack Protection**: Built-in timestamp tolerance checks (Stripe, Slack, Svix, Zoom) and stateful deduplication (`MemoryDedupeStore`).
- 🛡️ **Event Deduplication Store**: Pluggable `dedupeStore` interface with provider-aware event ID extraction to prevent duplicate event execution.
- 🔌 **Extensible Plugin System**: Register custom provider verifiers with `registerProvider()`.
- 🧪 **Testing Helpers**: `verihook/testing` signs webhooks for every built-in provider, so you can test your handlers end to end.
- 🏷️ **Typed Events**: Verified results include the parsed payload (`result.event`, typed per provider) and its name (`result.eventType`).
- 🩺 **Troubleshooting Hints**: Failed verifications say *why* (parsed body, wrong kind of secret, proxy URL mismatch) through `result.hint`.

---

## Installation

```bash
npm install verihook
# or
pnpm add verihook
# or
yarn add verihook
# or
bun add verihook
```

---

## Supported Providers

| Provider | Identifier | Required Headers / Notes |
| :--- | :--- | :--- |
| **Stripe** | `'stripe'` | `stripe-signature` |
| **GitHub** | `'github'` | `x-hub-signature-256` or `x-hub-signature` |
| **Shopify** | `'shopify'` | `x-shopify-hmac-sha256` |
| **Slack** | `'slack'` | `x-slack-signature`, `x-slack-request-timestamp` |
| **Twilio** | `'twilio'` | `x-twilio-signature` (Signs the public request URL: rebuilt from `x-forwarded-*`/`host` and `req.protocol` for relative URLs, or pass `options.url`; supports form payload signing and JSON `bodySHA256` flow) |
| **Svix** | `'svix'` | `svix-id`, `svix-timestamp`, `svix-signature` |
| **Resend** | `'resend'` | Uses Svix signatures |
| **Clerk** | `'clerk'` | Uses Svix signatures |
| **WhatsApp / Meta** | `'meta'`, `'whatsapp'` | `x-hub-signature-256` (Supports `verifyMetaChallenge` GET handshake) |
| **Discord** | `'discord'` | `x-signature-ed25519`, `x-signature-timestamp` (Ed25519 signature) |
| **Twitter / X** | `'twitter'`, `'x'` | `x-twitter-webhooks-signature` (Supports `verifyTwitterCrc` GET handshake) |
| **PayPal** | `'paypal'` | Transmission headers + `paypal-cert-url` (RSA-SHA256). Pass `{ webhookId }`; certs are only fetched from PayPal API hosts, or pin a PEM as `secret` |
| **LemonSqueezy** | `'lemonsqueezy'` | `x-signature` |
| **Paddle** | `'paddle'` | `paddle-signature` (`ts=...;h=...`) |
| **PagerDuty** | `'pagerduty'` | `x-pagerduty-signature` (`v1=...`) |
| **Webflow** | `'webflow'` | `x-webflow-signature`, `x-webflow-timestamp` |
| **WorkOS** | `'workos'` | `workos-signature` (`t=...,v1=...`) or `svix-signature` |
| **Linear** | `'linear'` | `linear-signature` |
| **Razorpay** | `'razorpay'` | `x-razorpay-signature` |
| **Square** | `'square'` | `x-square-hmacsha256-signature` |
| **Zoom** | `'zoom'` | `x-zm-signature`, `x-zm-request-timestamp` |
| **Cashfree** 🇮🇳 | `'cashfree'` | `x-webhook-signature`, `x-webhook-timestamp`. Secret: your PG client secret |
| **PhonePe** 🇮🇳 | `'phonepe'` | `authorization` (SHA-256 of the webhook credentials). Secret: `"username:password"`. The body isn't signed, so confirm the order status with PhonePe before fulfilling |
| **Mollie** 🇪🇺 | `'mollie'` | `x-mollie-signature` (`sha256=...`, next-gen webhooks; both signatures accepted during secret rotation) |
| **Adyen** 🇪🇺 | `'adyen'` | `additionalData.hmacSignature` in every notification item, or the `hmacsignature` header for platform/management webhooks. Secret: the hex HMAC key |
| **Checkout.com** 🇪🇺 | `'checkout'` | `cko-signature` |
| **Authorize.net** 🇺🇸 | `'authorizenet'` | `x-anet-signature` (`sha512=...`). Secret: your Signature Key |
| **Recurly** 🇺🇸 | `'recurly'` | `recurly-signature` (`<ms timestamp>,<sig>[,<sig>]`, JSON webhooks) |
| **Generic / Custom** | `'generic'` | Configurable header, algorithm, encoding |

---

## ⚡ CLI Toolchain (`npx verihook simulate` & `npx verihook listen`)

`verihook` includes a built-in zero-dependency CLI toolchain for simulating webhooks and proxying live events locally:

### 1. Webhook Simulation (`npx verihook simulate`)

Generate validly-signed HMAC payloads and POST them to your local server **without needing real SaaS accounts or webhooks**:

```bash
# Simulate a Stripe webhook
npx verihook simulate stripe --url http://localhost:3000/webhooks/stripe

# Simulate a GitHub issues event
npx verihook simulate github --event issues

# Simulate a WhatsApp message webhook
npx verihook simulate whatsapp --secret meta_app_secret_123

# Target a remote endpoint with --allow-remote
npx verihook simulate stripe --url https://staging.example.com/webhooks/stripe --allow-remote

# Output cURL command instead of sending POST
npx verihook simulate stripe --curl
```

### 2. Live Local Relay Proxy (`npx verihook listen`)

Run a live local relay proxy to intercept incoming webhooks, verify signatures in real-time, inspect formatted headers & payloads, and forward webhooks to your local server:

```bash
# Listen & forward Stripe webhooks with real-time signature verification
npx verihook listen stripe --forward-to http://localhost:3000/webhooks/stripe --secret whsec_test_secret_123

# Listen on custom port 8080 and forward GitHub webhooks
npx verihook listen github -p 8080 --forward-to http://localhost:4000/api/github
```

> 🛡️ **Security Features**:
> - **SSRF Protection**: Best-effort defense-in-depth origin validation blocking known cloud metadata endpoints and link-local IP addresses (*not a substitute for network-level isolation*):
>   - **AWS / GCP / Azure / DigitalOcean / Alibaba IMDS**: `169.254.169.254`, `169.254.170.2` (AWS ECS), `168.63.129.16` (Azure Wire Server), `100.100.100.200` (Alibaba IMDS), `metadata.google.internal`, `metadata.tencentyun.com`.
>   - **Link-Local Ranges & Alternative Encodings**: `169.254.0.0/16` subnet, `0.0.0.0/8`, IPv4-mapped IPv6 (`::ffff:169.254.x.x`), IPv6 Link-Local (`fe80::`), loopbacks (`127.0.0.1`, `0.0.0.0`, `::1`), decimal (`2852039166`), hex (`0xa9fea9fe`), and octal IP representations.
>   - **Non-HTTP Protocols**: Rejects `file://`, `ftp://`, `gopher://`, etc.
> - **Remote Server Notice**: Shows a warning notice when targeting non-local hosts unless `--allow-remote` is passed or `VERIHOOK_ALLOW_REMOTE=true` is set.
> - **Header Redaction**: Redacts sensitive secret tokens and signature headers in terminal log outputs.

---

## Quick Start

### Basic Usage

```ts
import { verifyWebhook } from 'verihook';

const result = await verifyWebhook('stripe', req, process.env.STRIPE_WEBHOOK_SECRET!);

if (result.valid) {
  console.log('Webhook verified! Timestamp:', result.timestamp);
  console.log('Event Type:', result.eventType);          // e.g. "payment_intent.succeeded"
  console.log('Event Data:', result.event?.data.object); // typed as StripeEvent
} else {
  console.error(`Verification failed [${result.code}]:`, result.reason);
}
```

### Typed Events (`result.event`, `result.eventType`)

When verification succeeds, the result carries the parsed payload. It's set only for valid requests, so you never act on an unverified body.

- `result.event` is the parsed JSON body, or the fields of a form post (Twilio, Slack slash commands). It is typed for every built-in provider (`StripeEvent`, `GitHubEvent`, `SvixEvent`, …). These lightweight types cover each provider's envelope and need no provider SDK.
- `result.eventType` is the event name, wherever the provider puts it:

| Provider | `eventType` comes from | Example |
| :--- | :--- | :--- |
| Stripe, Svix / Resend / Clerk, Square, Linear | body `type` | `invoice.paid` |
| GitHub | `x-github-event` header | `push` |
| Shopify | `x-shopify-topic` header | `orders/create` |
| Slack | body `type`, slash `command` or interaction `payload.type` | `event_callback` |
| Razorpay, Zoom, WorkOS | body `event` | `payment.captured` |
| PayPal, Paddle | body `event_type` | `transaction.completed` |
| LemonSqueezy | `meta.event_name` | `order_created` |
| PagerDuty | `event.event_type` | `incident.triggered` |
| Webflow | `triggerType` | `form_submission` |
| Meta / WhatsApp | `object` | `whatsapp_business_account` |
| Discord | `event.type`, or the interaction type | `APPLICATION_AUTHORIZED`, `PING` |
| Twitter / X | the `*_events` key | `tweet_create_events` |
| Generic / custom | body `type`, `event` or `event_type` | |

```ts
import { verifyWebhook } from 'verihook';

const result = await verifyWebhook('github', req, process.env.GITHUB_SECRET!);
if (result.valid && result.eventType === 'issues') {
  console.log(result.event?.action, result.event?.repository?.full_name);
}
```

You can pass your own type, for example the official SDK's type, for a precise shape:

```ts
import type Stripe from 'stripe';

const result = await verifyWebhook<Stripe.Event>('stripe', req, secret);
// result.event is Stripe.Event | undefined
```

The provider shortcuts (`verifyStripe<T>()`) and `createWebhookHandler<T>()` accept a type argument too.

### Strict Mode (Throw on Error)

```ts
import { verifyWebhookOrThrow, WebhookVerificationError } from 'verihook';

try {
  await verifyWebhookOrThrow('github', req, process.env.GITHUB_WEBHOOK_SECRET!);
  // Process verified payload...
} catch (err) {
  if (err instanceof WebhookVerificationError) {
    console.error(`[${err.provider}] Verification error (${err.code}):`, err.reason);
  }
}
```

### Provider Helper Functions

```ts
import { verifyStripe, verifyGitHub, verifySlack, verifyWhatsApp, verifyDiscord } from 'verihook';

// Provider-specific shortcut functions
await verifyStripe(req, process.env.STRIPE_SECRET!);
await verifyGitHub(req, process.env.GITHUB_SECRET!);
await verifySlack(req, process.env.SLACK_SECRET!);
await verifyWhatsApp(req, process.env.META_APP_SECRET!);
await verifyDiscord(req, process.env.DISCORD_PUBLIC_KEY!);
```

### Meta / WhatsApp Verification Handshake (`verifyMetaChallenge`)

Meta requires a GET challenge handshake when configuring webhooks in Meta App Dashboard:

```ts
import { verifyMetaChallenge } from 'verihook';

// In your GET /webhooks/whatsapp handler:
app.get('/webhooks/whatsapp', (req, res) => {
  const result = verifyMetaChallenge(req.query, process.env.META_VERIFY_TOKEN!);

  if (result.valid) {
    return res.status(200).send(result.challenge);
  }

  return res.status(403).send(result.reason);
});
```

### Replay Protection & Event Deduplication (`MemoryDedupeStore`)

Prevent duplicate event execution within tolerance windows (e.g. Stripe `evt_...`, Svix `msg_...`, GitHub delivery ID, or SHA-256 fallback):

```ts
import { verifyWebhook, MemoryDedupeStore, WebhookErrorCode } from 'verihook';

// Global or module-level deduplication store
const dedupeStore = new MemoryDedupeStore({
  ttlMs: 300_000, // 5 minutes TTL window
  maxSize: 10_000, // Capacity cap to bound memory usage
});

const result = await verifyWebhook('stripe', req, secret, {
  dedupeStore, // Automatically extracts event ID and rejects duplicate webhooks!
});

if (!result.valid && result.code === WebhookErrorCode.DUPLICATE_EVENT) {
  // Respond 2xx so the provider stops retrying an event you already handled.
  return res.status(200).json({ received: true, duplicate: true });
}

try {
  await processEvent(result);
} catch (err) {
  // Forget the event so the provider's retry is processed instead of rejected.
  await dedupeStore.delete(result.dedupeKey!);
  throw err;
}
```

`verihookExpress` and `createWebhookHandler` do both automatically: duplicates get `200 { received: true, duplicate: true }`, and a handler failure (thrown error or 5xx response) releases the event if your store implements the optional `delete(key)` method. `MemoryDedupeStore` is capped at 10,000 entries by default.

> [!NOTE]
> **Serverless & Multi-Instance Edge Deployments**: `MemoryDedupeStore` operates in-process per instance. For serverless (AWS Lambda, Vercel Edge, Cloudflare Workers) or multi-replica deployments, implement a shared distributed store using the `DedupeStore` interface.
> 
> See copy-pasteable reference implementations in [`examples/dedupe-stores/`](./examples/dedupe-stores/):
> - ⚡ **[Upstash Redis (REST/Fetch-based)](./examples/dedupe-stores/upstash-redis.ts)**: Recommended for zero-TCP HTTP edge runtimes (Cloudflare Workers, Vercel Edge).
> - ☁️ **[Cloudflare Workers KV](./examples/dedupe-stores/cloudflare-kv.ts)**: Native KV store for Cloudflare Workers (eventually consistent).

### Error Handling & Error Codes

`verihook` provides structured, type-safe error codes via the exported `WebhookErrorCode` enum:

```ts
import { verifyWebhook, WebhookErrorCode } from 'verihook';

const result = await verifyWebhook('stripe', req, secret);

if (!result.valid) {
  switch (result.code) {
    case WebhookErrorCode.INVALID_SIGNATURE:
      console.error('Signature mismatch — payload altered or secret incorrect');
      break;
    case WebhookErrorCode.EXPIRED_TIMESTAMP:
      console.error('Timestamp outside allowed tolerance window');
      break;
    case WebhookErrorCode.MISSING_HEADER:
      console.error('Required signature header missing');
      break;
    case WebhookErrorCode.INVALID_BODY:
      console.error('Raw body missing — body was pre-parsed before verification');
      break;
  }
}
```

#### Available Error Codes

| Error Code | Description |
| :--- | :--- |
| `WebhookErrorCode.INVALID_SIGNATURE` | HMAC signature calculation did not match incoming header. |
| `WebhookErrorCode.EXPIRED_TIMESTAMP` | Webhook timestamp exceeds tolerance window (default 300s). |
| `WebhookErrorCode.MISSING_HEADER` | Required provider signature header is missing from request. |
| `WebhookErrorCode.MISSING_URL` | Request URL is missing (required for Twilio / Square). |
| `WebhookErrorCode.INVALID_SECRET` | Webhook secret was empty or not provided. |
| `WebhookErrorCode.INVALID_BODY` | Plain JS object passed without `rawBody`. |
| `WebhookErrorCode.UNSUPPORTED_PROVIDER` | Unrecognized provider identifier. |
| `WebhookErrorCode.DUPLICATE_EVENT` | Duplicate webhook event detected within deduplication TTL window. |
| `WebhookErrorCode.UNKNOWN_ERROR` | Unexpected error during processing (original error attached to `result.error`). |

#### Troubleshooting Hints (`result.hint`)

When verification fails for a reason verihook can recognize, the result includes a `hint` with the likely cause and the fix. For example:

- the body was parsed and re-serialized (its size no longer matches `content-length`), or its stream was already read;
- the secret is the wrong kind (a Stripe API key `sk_...` instead of the `whsec_...` signing secret), or has stray whitespace or quotes;
- the request has another provider's headers (e.g. verifying a GitHub webhook as `'stripe'`);
- Twilio/Square signatures were checked against an internal URL behind a proxy;
- a replayed test fixture has an expired timestamp.

```ts
const result = await verifyWebhook('stripe', req, secret);
if (!result.valid) {
  logger.warn({ code: result.code, reason: result.reason, hint: result.hint });
}
```

Hints are also included on telemetry events and on `WebhookVerificationError.hint`. Outside production and test runs, each distinct hint is printed once with `console.warn`. The middlewares don't include hints in HTTP responses, and neither should you: they describe your configuration.

---

## Framework Integration Examples

### Next.js App Router (1-Line Route Handler Factory)

```ts
import { createWebhookHandler } from 'verihook/next'; // or 'verihook'

export const POST = createWebhookHandler('github', process.env.GITHUB_SECRET!, async (payload, result) => {
  // Executed ONLY if signature is 100% valid!
  console.log(`Verified ${result.eventType} event:`, result.event?.action); // result.event is a GitHubEvent
});
```

### Express.js (1-Line Middleware)

```ts
import express from 'express';
import { verihookExpress, type VerihookRequestAdditions } from 'verihook/express'; // or 'verihook'
import type { StripeEvent } from 'verihook';

const app = express();

app.post(
  '/webhooks/stripe',
  verihookExpress('stripe', process.env.STRIPE_SECRET!, {
    maxBodySize: 2 * 1024 * 1024, // Optional payload size limit in bytes (default 2MB)
  }),
  (req, res) => {
    // req.verihook is only set when the signature is valid
    const { event, eventType } = (req as Request & VerihookRequestAdditions<StripeEvent>).verihook!;
    console.log('Verified stripe event:', eventType, event?.data.object);
    res.json({ received: true });
  }
);
```

### Hono / Cloudflare Workers / Bun / Deno

```ts
import { Hono } from 'hono';
import { verihookHono, type VerihookVariables } from 'verihook/hono';
import type { StripeEvent } from 'verihook';

const app = new Hono<{ Bindings: { STRIPE_SECRET: string }; Variables: VerihookVariables<StripeEvent> }>();

app.post('/webhooks/stripe', verihookHono('stripe', (c) => c.env.STRIPE_SECRET), (c) => {
  const { event, eventType } = c.get('verihook'); // the body is still readable with c.req.json()
  return c.json({ received: true });
});
```

### Fastify

Fastify parses JSON before your route runs, so register `verihookRawBody` in the scope of your webhook routes. It keeps `request.rawBody` and still parses JSON and form bodies into `request.body`.

```ts
import Fastify from 'fastify';
import { verihookFastify, verihookRawBody, type VerihookFastifyRequest } from 'verihook/fastify';
import type { StripeEvent } from 'verihook';

const app = Fastify();
await app.register(verihookRawBody);

app.post('/webhooks/stripe', { preHandler: verihookFastify('stripe', process.env.STRIPE_SECRET!) }, async (request) => {
  const { event } = (request as typeof request & VerihookFastifyRequest<StripeEvent>).verihook!;
  return { received: true };
});
```

### NestJS

Create the app with `rawBody: true` so Nest keeps the raw body, then guard the route. Works on the Express and Fastify platforms.

```ts
// main.ts
const app = await NestFactory.create(AppModule, { rawBody: true });

// webhooks.controller.ts
import { createVerihookGuard, type VerihookNestRequest } from 'verihook/nestjs';

@Post('webhooks/stripe')
@UseGuards(createVerihookGuard('stripe', process.env.STRIPE_SECRET!))
handle(@Req() req: Request & VerihookNestRequest<StripeEvent>) {
  const { event } = req.verihook!;
}
```

On failure the guard sends the reply itself. To let your exception filters shape it, pass `exceptionFactory: (result) => new UnauthorizedException(result.reason)`.

### Nuxt / Nitro / h3

```ts
// server/api/webhooks/stripe.post.ts
import { createWebhookHandler } from 'verihook/h3';

export default defineEventHandler(
  createWebhookHandler('stripe', process.env.STRIPE_SECRET!, async (payload, result, event) => {
    // result.event is a StripeEvent
  }),
);
```

Works with h3 v1 (Nuxt 3) and h3 v2. `readBody(event)` still works inside the handler.

### SvelteKit, Remix / React Router, Astro

Each one exports `createWebhookHandler(provider, secret, handler, options?)`. The handler receives `(payload, result, frameworkContext)`. A secret function receives the same context (for example, platform env bindings).

```ts
// SvelteKit: src/routes/webhooks/github/+server.ts
import { createWebhookHandler } from 'verihook/sveltekit';
export const POST = createWebhookHandler('github', env.GITHUB_SECRET, async (payload, result) => { /* ... */ });

// Remix / React Router: app/routes/webhooks.github.ts
import { createWebhookHandler } from 'verihook/remix';
export const action = createWebhookHandler('github', process.env.GITHUB_SECRET!, async (payload, result) => { /* ... */ });

// Astro: src/pages/api/webhooks/github.ts (server-rendered route)
import { createWebhookHandler } from 'verihook/astro';
export const prerender = false;
export const POST = createWebhookHandler('github', import.meta.env.GITHUB_SECRET, async (payload, result) => { /* ... */ });
```

### AWS Lambda (API Gateway REST v1, HTTP API v2, Function URLs)

```ts
import { createWebhookHandler } from 'verihook/lambda';

export const handler = createWebhookHandler('stripe', process.env.STRIPE_SECRET!, async (payload, result, event, context) => {
  // return nothing for 200 { received: true }, or your own { statusCode, headers, body }
});
```

Base64 bodies are decoded before verification. For providers that sign the URL (Twilio, Square), the URL is rebuilt from the `Host` header and the request path including the stage. Behind a custom domain with a base-path mapping, pass `options.url`.

### Shared adapter behaviour

Every adapter (`verihook/express`, `/next`, `/fastify`, `/hono`, `/h3`, `/sveltekit`, `/remix`, `/astro`, `/lambda`, `/nestjs`) behaves the same way:

| Situation | Response |
| :--- | :--- |
| Invalid / missing / expired signature | `401 { error, code }`, unless you pass `onError` (`exceptionFactory` for NestJS) |
| Duplicate event (`dedupeStore`) | `200 { received: true, duplicate: true }`, so the provider stops retrying |
| Body over `maxBodySize` (default 2MB) | `413 { code: "PAYLOAD_TOO_LARGE" }` |
| Exception during verification | `500` with a generic message. Details go to `onError` and telemetry only. |
| Your handler throws or responds `>= 500` | The dedupe key is released, so the provider's retry is processed |

Adapters have no runtime dependency on their framework.

---

## Options & Custom Providers

### Config Options

```ts
await verifyWebhook('stripe', req, secret, {
  tolerance: 600, // Customize maximum allowed timestamp drift in seconds (default: 300)
  now: Math.floor(Date.now() / 1000), // Override current timestamp for testing
  url: 'https://example.com/api/twilio', // Override URL for Twilio / Square
  maxBodySize: 5 * 1024 * 1024, // Configure maximum unparsed payload streaming limit in bytes
  dedupeStore, // Pass DedupeStore instance (e.g. MemoryDedupeStore or Redis)
  dedupeTtlMs: 600_000, // Custom TTL for deduplication entries in milliseconds
  eventId: 'evt_custom_override', // Explicitly override provider event ID
});
```

### Custom HMAC Signature Verification (`'generic'`)

```ts
await verifyWebhook('generic', req, secret, {
  headerName: 'x-custom-signature',
  algorithm: 'sha256', // 'sha256' | 'sha1' | 'sha512'
  encoding: 'hex',     // 'hex' | 'base64' | 'prefix-hex'
});
```

### Registering Custom Provider Plugins

```ts
import { registerProvider } from 'verihook';

registerProvider({
  name: 'my-service',
  async verify(req, secret) {
    const signature = req.headers['x-myservice-sig'];
    // ... custom verification logic
    return { valid: true, provider: 'my-service' };
  },
  // Optional: where result.eventType comes from (defaults to body type / event / event_type)
  eventType: (event, req) => req.headers['x-myservice-event'],
});

await verifyWebhook('my-service', req, secret);
```

Want it built in? [CONTRIBUTING.md](./CONTRIBUTING.md) shows how to add a provider in 5 steps.

---

## Testing Your Webhook Handlers (`verihook/testing`)

`signWebhook()` builds a correctly signed request for any built-in provider, so you can test your handlers without real provider traffic:

```ts
import { signWebhook } from 'verihook/testing';
import request from 'supertest';

it('handles payment_intent.succeeded', async () => {
  const hook = await signWebhook('stripe', {
    secret: process.env.STRIPE_WEBHOOK_SECRET!,
    payload: { id: 'evt_1', type: 'payment_intent.succeeded', data: { object: {} } },
  });

  await request(app)
    .post('/webhooks/stripe')
    .set(hook.headers)
    .send(hook.body) // send the exact signed string
    .expect(200);
});
```

For handlers that take a Fetch `Request` (Next.js route handlers, Hono, Cloudflare Workers), use `createSignedRequest()`:

```ts
import { createSignedRequest } from 'verihook/testing';
import { POST } from '@/app/api/webhooks/github/route';

const req = await createSignedRequest('github', { secret: 'test', event: 'push', payload: { ref: 'refs/heads/main' } });
const res = await POST(req);
```

| Option | Description |
| :--- | :--- |
| `secret` | Signing secret, as you pass it to `verifyWebhook()` (required except for Discord). |
| `payload` | Object (JSON-serialized) or exact string body. Default `{}`. |
| `form` | Form fields sent as `application/x-www-form-urlencoded` (Slack, Twilio). |
| `url` | Public URL signed by Twilio and Square. Default `https://example.com/webhooks/<provider>`. |
| `timestamp` | Unix seconds. Default now. Use with `options.now` for fixed fixtures. |
| `webhookId` | `svix-id` for Svix, Resend and Clerk. |
| `event` | `x-github-event` for GitHub. Default `ping`. |
| `privateKey` | Discord: 32-byte Ed25519 seed (hex). Omitted: a key pair is generated. The public key is returned as `secret`. |
| `headerName`, `algorithm`, `encoding` | Generic provider settings, matching your `verifyWebhook()` options. |
| `headers` | Extra headers to include (e.g. `x-shopify-topic`). |

The result is `{ provider, method, url, headers, body, secret }`. PayPal can't be signed locally, because PayPal signs with its own private key.

---

## Testing & Verification Scripts

The repository includes pre-commit, pre-release, regression, and comprehensive testing scripts to enforce strict code quality and security standards:

```bash
# Run complete end-to-end test suite (Format + Typecheck + Coverage + Regression + Build + CLI + Module Exports)
npm run test:all

# Run end-to-end regression test suite across all 20+ providers & middleware adapters
npm run test:regression

# Run format check, typecheck, coverage tests, and package build
npm run verify

# Format codebase with Prettier
npm run format

# Run unit tests with V8 coverage report
npm run test:coverage

# Perform security vulnerability audit
npm run audit
```

---

## Contributing

Contributions are welcome, especially new providers. See [CONTRIBUTING.md](./CONTRIBUTING.md) for setup, the provider template and the PR checklist.

---

## License

MIT © Piyush Anand
