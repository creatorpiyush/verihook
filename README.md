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

📖 Read the full [Architecture & Technical Specification](./ARCHITECTURE.md).

---

## Features

- ⚡ **Zero Runtime Dependencies**: Powered by standard Web Crypto API (`crypto.subtle`) with Node.js fallback.
- 🚀 **1-Line Framework Middlewares**: Native Express middleware (`verihookExpress`) and Next.js Route Handler factory (`createWebhookHandler`).
- 🛡️ **Hardened & Secure**: Built-in SSRF origin protection, unparsed payload stream byte limits (`maxBodySize`), and standard HTTP security headers (`nosniff`, `DENY`).
- 🌐 **Edge Ready**: Runs anywhere — Node.js, Vercel Edge, Cloudflare Workers, Deno, Bun, Next.js, Hono, Express, Fastify.
- 🔐 **Timing-Safe**: Protects against side-channel timing attacks out of the box.
- 🎯 **Unified Typed API**: Simple `verifyWebhook(provider, req, secret)` interface across all providers with zero `any` types.
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
| **WhatsApp / Meta** | `'meta'`, `'whatsapp'` | `x-hub-signature-256` (Supports `verifyMetaChallenge` GET handshake) |
| **Discord** | `'discord'` | `x-signature-ed25519`, `x-signature-timestamp` (Ed25519 signature) |
| **Twitter / X** | `'twitter'`, `'x'` | `x-twitter-webhooks-signature` (Supports `verifyTwitterCrc` GET handshake) |
| **PayPal** | `'paypal'` | Transmission headers + `crc32` payload signing (RSA-SHA256 & HMAC) |
| **LemonSqueezy** | `'lemonsqueezy'` | `x-signature` |
| **Paddle** | `'paddle'` | `paddle-signature` (`ts=...;h=...`) |
| **PagerDuty** | `'pagerduty'` | `x-pagerduty-signature` (`v1=...`) |
| **Webflow** | `'webflow'` | `x-webflow-signature`, `x-webflow-timestamp` |
| **WorkOS** | `'workos'` | `workos-signature` (`t=...,v1=...`) or `svix-signature` |
| **Linear** | `'linear'` | `linear-signature` |
| **Razorpay** | `'razorpay'` | `x-razorpay-signature` |
| **Square** | `'square'` | `x-square-hmacsha256-signature` |
| **Zoom** | `'zoom'` | `x-zm-signature`, `x-zm-request-timestamp` |
| **Generic / Custom** | `'generic'` | Configurable header, algorithm, encoding |

---

## ⚡ CLI Simulator (`npx verihook simulate`)

Test your webhook endpoint locally **without needing real SaaS accounts or webhooks**! The CLI generates validly-signed HMAC payloads and POSTs them to your server:

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

> 🛡️ **Security Features**:
> - **SSRF Protection**: Strictly blocks requests targeting cloud metadata endpoints and link-local IP addresses:
>   - **AWS / GCP / Azure / DigitalOcean / Alibaba IMDS**: `169.254.169.254`, `169.254.170.2` (AWS ECS), `168.63.129.16` (Azure Wire Server), `100.100.100.200` (Alibaba IMDS), `metadata.google.internal`, `metadata.tencentyun.com`.
>   - **Link-Local Ranges & Alternative Encodings**: `169.254.0.0/16` subnet, IPv4-mapped IPv6 (`::ffff:169.254.x.x`), IPv6 Link-Local (`fe80::`), decimal (`2852039166`), hex (`0xa9fea9fe`), and octal IP representations.
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

### Next.js App Router (1-Line Route Handler Factory)

```ts
import { createWebhookHandler } from 'verihook/next'; // or 'verihook'

export const POST = createWebhookHandler('github', process.env.GITHUB_SECRET!, async (payload, result) => {
  // Executed ONLY if signature is 100% valid!
  console.log('Verified issue event:', (payload as any).action);
});
```

### Express.js (1-Line Middleware)

```ts
import express from 'express';
import { verihookExpress } from 'verihook/express'; // or 'verihook'

const app = express();

app.post(
  '/webhooks/stripe',
  verihookExpress('stripe', process.env.STRIPE_SECRET!, {
    maxBodySize: 2 * 1024 * 1024, // Optional payload size limit in bytes (default 2MB)
  }),
  (req, res) => {
    // req.verifiedPayload is guaranteed valid and raw body preserved!
    console.log('Verified stripe event:', (req as any).verifiedPayload.type);
    res.json({ received: true });
  }
);
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
  maxBodySize: 5 * 1024 * 1024, // Configure maximum unparsed payload streaming limit in bytes
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

## License

MIT © Piyush Anand
