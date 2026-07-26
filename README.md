# verihook 🪝

> **Universal, typed webhook signature verifier** for TypeScript and JavaScript.

[![npm version](https://img.shields.io/npm/v/verihook.svg)](https://www.npmjs.com/package/verihook)
[![license](https://img.shields.io/npm/l/verihook.svg)](https://github.com/creatorpiyush/verihook/blob/main/LICENSE)

`verihook` provides a unified, strongly-typed API for verifying webhook signatures across popular services (**Stripe, GitHub, Shopify, Slack, Twilio, Svix/Resend/Clerk, Linear, Razorpay, Zoom, Square, and custom webhooks**).

No more hunting down bespoke HMAC code snippets for every service or installing 10 heavy SDK dependencies just to verify incoming webhooks!

📖 Read the full [Architecture & Technical Specification](./ARCHITECTURE.md).

---

## Features

- ⚡ **Zero Runtime Dependencies**: Powered by standard Web Crypto API (`crypto.subtle`) with Node.js fallback.
- 🌐 **Edge Ready**: Runs anywhere — Node.js, Vercel Edge, Cloudflare Workers, Deno, Bun, Next.js, Hono, Express, Fastify.
- 🔐 **Timing-Safe**: Protects against side-channel timing attacks out of the box.
- 🎯 **Unified Typed API**: Simple `verifyWebhook(provider, req, secret)` interface across all providers.
- ⏳ **Replay Attack Protection**: Built-in configurable timestamp tolerance checks (Stripe, Slack, Svix, Zoom).
- 🔌 **Extensible Plugin System**: Register custom provider verifiers with `registerProvider()`.

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
| **Twilio** | `'twilio'` | `x-twilio-signature` (Requires request URL; supports form payload signing and JSON `bodySHA256` flow) |
| **Svix** | `'svix'` | `svix-id`, `svix-timestamp`, `svix-signature` |
| **Resend** | `'resend'` | Uses Svix signatures |
| **Clerk** | `'clerk'` | Uses Svix signatures |
| **Linear** | `'linear'` | `linear-signature` |
| **Razorpay** | `'razorpay'` | `x-razorpay-signature` |
| **Square** | `'square'` | `x-square-hmacsha256-signature` |
| **Zoom** | `'zoom'` | `x-zm-signature`, `x-zm-request-timestamp` |
| **Generic / Custom** | `'generic'` | Configurable header, algorithm, encoding |

---

## Quick Start

### Basic Usage

```ts
import { verifyWebhook } from 'verihook';

const result = await verifyWebhook('stripe', req, process.env.STRIPE_WEBHOOK_SECRET!);

if (result.valid) {
  console.log('Webhook verified! Timestamp:', result.timestamp);

  // Parse raw body string/Buffer to access event payload data
  const event = JSON.parse(req.body.toString('utf-8'));
  console.log('Event Type:', event.type);          // e.g. "payment_intent.succeeded"
  console.log('Event Data:', event.data.object);   // e.g. amount, customer ID, status
} else {
  console.error(`Verification failed [${result.code}]:`, result.reason);
}
```

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
import { verifyStripe, verifyGitHub, verifySlack, verifyResend, verifyClerk } from 'verihook';

// Provider-specific shortcut functions
await verifyStripe(req, process.env.STRIPE_SECRET!);
await verifyGitHub(req, process.env.GITHUB_SECRET!);
await verifySlack(req, process.env.SLACK_SECRET!);
await verifyResend(req, process.env.RESEND_SECRET!);
await verifyClerk(req, process.env.CLERK_SECRET!);
```

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
| `WebhookErrorCode.UNKNOWN_ERROR` | Unexpected error during processing (original error attached to `result.error`). |

---

## Framework Integration Examples

### Next.js App Router (Route Handler)

```ts
import { verifyWebhook } from 'verihook';
import { NextResponse } from 'next/server';

export async function POST(req: Request) {
  const result = await verifyWebhook('stripe', req, process.env.STRIPE_WEBHOOK_SECRET!);

  if (!result.valid) {
    return NextResponse.json({ error: result.reason }, { status: 401 });
  }

  const payload = await req.json();
  // Handle verified event...

  return NextResponse.json({ received: true });
}
```

### Express.js

> **Note**: Ensure you capture the raw body as a string or Buffer before JSON parsing!

```ts
import express from 'express';
import { verifyWebhook } from 'verihook';

const app = express();

app.post('/api/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const result = await verifyWebhook('github', req, process.env.GITHUB_SECRET!);

  if (!result.valid) {
    return res.status(401).json({ error: result.reason });
  }

  // Parse raw body string/Buffer to process verified event data
  const payload = JSON.parse(req.body.toString('utf-8'));
  console.log('Verified Event Action:', payload.action);
  console.log('Verified Event Data:', payload.issue || payload.data?.object);

  res.status(200).json({ success: true });
});
```

### Hono / Cloudflare Workers

```ts
import { Hono } from 'hono';
import { verifyWebhook } from 'verihook';

const app = new Hono();

app.post('/webhook', async (c) => {
  const result = await verifyWebhook('shopify', c.req.raw, c.env.SHOPIFY_SECRET);

  if (!result.valid) {
    return c.json({ error: result.reason }, 401);
  }

  return c.json({ status: 'ok' });
});

export default app;
```

---

## Options & Custom Providers

### Config Options

```ts
await verifyWebhook('stripe', req, secret, {
  tolerance: 600, // Customize maximum allowed timestamp drift in seconds (default: 300)
  now: Math.floor(Date.now() / 1000), // Override current timestamp for testing
  url: 'https://example.com/api/twilio', // Override URL for Twilio / Square
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
});

await verifyWebhook('my-service', req, secret);
```

---

## License

MIT © Piyush Anand
