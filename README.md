# verihook 🪝

> **Universal, typed webhook signature verifier** for TypeScript and JavaScript.

[![npm version](https://img.shields.io/npm/v/verihook.svg)](https://www.npmjs.com/package/verihook)
[![JSR](https://jsr.io/badges/@verihook/verihook)](https://jsr.io/@verihook/verihook)
[![docs](https://img.shields.io/badge/docs-creatorpiyush.github.io%2Fverihook-blue.svg)](https://creatorpiyush.github.io/verihook/)
[![license](https://img.shields.io/npm/l/verihook.svg)](https://github.com/creatorpiyush/verihook/blob/main/LICENSE)
[![CI Verification](https://github.com/creatorpiyush/verihook/actions/workflows/pr-verify.yml/badge.svg)](https://github.com/creatorpiyush/verihook/actions)
[![coverage](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fcreatorpiyush%2Fverihook%2Fbadges%2Fcoverage.json)](https://github.com/creatorpiyush/verihook/actions/workflows/coverage-badge.yml)
[![bundle size](https://img.shields.io/bundlejs/size/verihook?exports=verifyWebhook)](https://bundlejs.com/?q=verihook&treeshake=%5B%7BverifyWebhook%7D%5D)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/creatorpiyush/verihook/badge)](https://securityscorecards.dev/viewer/?uri=github.com/creatorpiyush/verihook)
[![zero dependencies](https://img.shields.io/badge/dependencies-0-success.svg)](https://www.npmjs.com/package/verihook)
[![TypeScript](https://img.shields.io/badge/TypeScript-Strict-blue.svg)](https://www.typescriptlang.org/)
[![npm downloads](https://img.shields.io/npm/dm/verihook.svg)](https://www.npmjs.com/package/verihook)

**[Documentation](https://creatorpiyush.github.io/verihook/)** · [Providers](https://creatorpiyush.github.io/verihook/providers/) · [Frameworks](https://creatorpiyush.github.io/verihook/frameworks/nextjs/) · [Troubleshooting](https://creatorpiyush.github.io/verihook/troubleshooting/) · [Changelog](./CHANGELOG.md)

`verihook` verifies webhook signatures from Stripe, GitHub, Shopify, Slack, Twilio, Clerk, Resend, Paddle, Razorpay and 30+ other providers with one typed API, so you don't copy a different HMAC snippet for every service or install ten SDKs.

- **Zero dependencies.** Web Crypto, so it runs on Node.js 18.17+, Deno, Bun, Cloudflare Workers and Vercel Edge.
- **One-line adapters** for Next.js, Express, Fastify, Hono, NestJS, Nuxt/h3, SvelteKit, Remix/React Router, Astro and AWS Lambda. They keep the raw body for you.
- **Says what went wrong.** Failed checks return an error code and a hint: a parsed body, an API key instead of the signing secret, a proxy rewriting the URL.
- **Typed events.** `result.event` is the parsed payload, typed per provider; `result.eventType` is its name.
- **Testing helpers.** `verihook/testing` signs requests for every provider; `npx verihook simulate` sends them to your local server.
- **Hardened.** Timing-safe comparison, replay windows, deduplication keyed only on signed data, body size limits. Conformance-tested against the official Stripe, GitHub, Svix and Twilio SDKs, and fuzz-tested.
- **Small.** One provider from `verihook/stripe` is ~4 kB min+brotli; all of them ~10 kB.

## Install

```bash
npm install verihook        # or pnpm add / yarn add / bun add
deno add jsr:@verihook/verihook
```

## Quick start

```ts
import { verifyWebhook } from 'verihook';

export async function POST(request: Request) {
  const result = await verifyWebhook('stripe', request, process.env.STRIPE_WEBHOOK_SECRET!);

  if (!result.valid) {
    console.warn(result.code, result.reason, result.hint);
    return new Response('Invalid signature', { status: 401 });
  }

  console.log(result.eventType, result.event); // "invoice.paid", typed as StripeEvent
  return Response.json({ received: true });
}
```

`request` is a Fetch `Request` or `{ headers, body, url? }` with the **raw** body. Signatures cover the exact bytes sent, so verify before any JSON parser touches the body ([why](https://creatorpiyush.github.io/verihook/guides/raw-body/)).

## Frameworks

```ts
// Next.js App Router: app/api/webhooks/github/route.ts
import { createWebhookHandler } from 'verihook/next';

export const POST = createWebhookHandler('github', process.env.GITHUB_WEBHOOK_SECRET!, async (payload, result) => {
  // runs only for a valid signature
});
```

```ts
// Express: register before express.json()
import { verihookExpress } from 'verihook/express';

app.post('/webhooks/stripe', verihookExpress('stripe', process.env.STRIPE_WEBHOOK_SECRET!), (req, res) => {
  res.json({ received: true });
});
```

| Framework | Import | Guide |
| :--- | :--- | :--- |
| Next.js | `verihook/next` | [docs](https://creatorpiyush.github.io/verihook/frameworks/nextjs/) |
| Express | `verihook/express` | [docs](https://creatorpiyush.github.io/verihook/frameworks/express/) |
| Fastify | `verihook/fastify` | [docs](https://creatorpiyush.github.io/verihook/frameworks/fastify/) |
| Hono / Workers / Bun / Deno | `verihook/hono` | [docs](https://creatorpiyush.github.io/verihook/frameworks/hono/) |
| NestJS | `verihook/nestjs` | [docs](https://creatorpiyush.github.io/verihook/frameworks/nestjs/) |
| Nuxt / Nitro / h3 | `verihook/h3` | [docs](https://creatorpiyush.github.io/verihook/frameworks/nuxt/) |
| SvelteKit | `verihook/sveltekit` | [docs](https://creatorpiyush.github.io/verihook/frameworks/sveltekit/) |
| Remix / React Router | `verihook/remix` | [docs](https://creatorpiyush.github.io/verihook/frameworks/remix/) |
| Astro | `verihook/astro` | [docs](https://creatorpiyush.github.io/verihook/frameworks/astro/) |
| AWS Lambda | `verihook/lambda` | [docs](https://creatorpiyush.github.io/verihook/frameworks/aws-lambda/) |

Every adapter answers `401` to a bad signature, `413` to an oversized body and `200` to a duplicate event.

## Providers

Each page says where to find the secret, which headers are sent and how to verify in every framework.

| | | |
| :--- | :--- | :--- |
| [Stripe](https://creatorpiyush.github.io/verihook/providers/stripe/) `stripe` | [GitHub](https://creatorpiyush.github.io/verihook/providers/github/) `github` | [Shopify](https://creatorpiyush.github.io/verihook/providers/shopify/) `shopify` |
| [Slack](https://creatorpiyush.github.io/verihook/providers/slack/) `slack` | [Twilio](https://creatorpiyush.github.io/verihook/providers/twilio/) `twilio` | [Svix](https://creatorpiyush.github.io/verihook/providers/svix/) `svix` |
| [Resend](https://creatorpiyush.github.io/verihook/providers/resend/) `resend` | [Clerk](https://creatorpiyush.github.io/verihook/providers/clerk/) `clerk` | [Meta / WhatsApp](https://creatorpiyush.github.io/verihook/providers/meta/) `meta` |
| [Discord](https://creatorpiyush.github.io/verihook/providers/discord/) `discord` | [X (Twitter)](https://creatorpiyush.github.io/verihook/providers/twitter/) `twitter` | [PayPal](https://creatorpiyush.github.io/verihook/providers/paypal/) `paypal` |
| [Lemon Squeezy](https://creatorpiyush.github.io/verihook/providers/lemonsqueezy/) `lemonsqueezy` | [Paddle](https://creatorpiyush.github.io/verihook/providers/paddle/) `paddle` | [PagerDuty](https://creatorpiyush.github.io/verihook/providers/pagerduty/) `pagerduty` |
| [Webflow](https://creatorpiyush.github.io/verihook/providers/webflow/) `webflow` | [WorkOS](https://creatorpiyush.github.io/verihook/providers/workos/) `workos` | [Linear](https://creatorpiyush.github.io/verihook/providers/linear/) `linear` |
| [Razorpay](https://creatorpiyush.github.io/verihook/providers/razorpay/) `razorpay` | [Square](https://creatorpiyush.github.io/verihook/providers/square/) `square` | [Zoom](https://creatorpiyush.github.io/verihook/providers/zoom/) `zoom` |
| [Cashfree](https://creatorpiyush.github.io/verihook/providers/cashfree/) `cashfree` | [PhonePe](https://creatorpiyush.github.io/verihook/providers/phonepe/) `phonepe` | [Mollie](https://creatorpiyush.github.io/verihook/providers/mollie/) `mollie` |
| [Adyen](https://creatorpiyush.github.io/verihook/providers/adyen/) `adyen` | [Checkout.com](https://creatorpiyush.github.io/verihook/providers/checkout/) `checkout` | [Authorize.net](https://creatorpiyush.github.io/verihook/providers/authorizenet/) `authorizenet` |
| [Recurly](https://creatorpiyush.github.io/verihook/providers/recurly/) `recurly` | [GitLab](https://creatorpiyush.github.io/verihook/providers/gitlab/) `gitlab` | [Bitbucket](https://creatorpiyush.github.io/verihook/providers/bitbucket/) `bitbucket` |
| [Vercel](https://creatorpiyush.github.io/verihook/providers/vercel/) `vercel` | [Sentry](https://creatorpiyush.github.io/verihook/providers/sentry/) `sentry` | [Twitch EventSub](https://creatorpiyush.github.io/verihook/providers/twitch/) `twitch` |
| [Telegram](https://creatorpiyush.github.io/verihook/providers/telegram/) `telegram` | [Postmark](https://creatorpiyush.github.io/verihook/providers/postmark/) `postmark` | [SendGrid](https://creatorpiyush.github.io/verihook/providers/sendgrid/) `sendgrid` |
| [Mailgun](https://creatorpiyush.github.io/verihook/providers/mailgun/) `mailgun` | [HubSpot](https://creatorpiyush.github.io/verihook/providers/hubspot/) `hubspot` | [Intercom](https://creatorpiyush.github.io/verihook/providers/intercom/) `intercom` |
| [Calendly](https://creatorpiyush.github.io/verihook/providers/calendly/) `calendly` | [Typeform](https://creatorpiyush.github.io/verihook/providers/typeform/) `typeform` |  |

Anything else: the `generic` HMAC verifier or [your own provider](https://creatorpiyush.github.io/verihook/guides/custom-providers/).

## Testing your handlers

```ts
import { signWebhook } from 'verihook/testing';

const hook = await signWebhook('stripe', {
  secret: 'whsec_test',
  payload: { id: 'evt_1', type: 'payment_intent.succeeded' },
});

await request(app).post('/webhooks/stripe').set(hook.headers).send(hook.body).expect(200);
```

```bash
npx verihook simulate stripe --url http://localhost:3000/webhooks/stripe
```

See [Testing](https://creatorpiyush.github.io/verihook/guides/testing/) and the [CLI](https://creatorpiyush.github.io/verihook/guides/cli/), including the `listen` relay.

## More

- [Deduplication and replays](https://creatorpiyush.github.io/verihook/guides/dedupe/): reject retried and replayed deliveries, in memory or in Redis/KV.
- [Typed events](https://creatorpiyush.github.io/verihook/guides/typed-events/) and [options](https://creatorpiyush.github.io/verihook/reference/options/): strict mode, telemetry, tolerances.
- [Edge runtimes and bundle size](https://creatorpiyush.github.io/verihook/guides/edge-and-bundles/): per-provider imports.
- [Architecture](./ARCHITECTURE.md) and [Security policy](./SECURITY.md).

## Contributing

Contributions are welcome, especially new providers. [CONTRIBUTING.md](./CONTRIBUTING.md) covers setup, the provider template and the PR checklist. `npm run test:all` runs everything CI runs.

## License

MIT © Piyush Anand
