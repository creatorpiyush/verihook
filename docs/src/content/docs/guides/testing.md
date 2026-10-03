---
title: Testing your handlers
description: Sign webhooks for any provider in unit and integration tests with verihook/testing, or send them to a local server with npx verihook simulate.
sidebar:
  order: 2
---

`verihook/testing` builds correctly signed requests for every built-in provider except PayPal, so you can test handlers end to end without real provider traffic.

## With supertest (Express, Fastify, NestJS)

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
    .send(hook.body) // the exact signed string
    .expect(200);
});
```

## With a Fetch Request (Next.js, Hono, Workers)

```ts
import { createSignedRequest } from 'verihook/testing';
import { POST } from '@/app/api/webhooks/github/route';

const req = await createSignedRequest('github', {
  secret: 'test_secret',
  event: 'push',
  payload: { ref: 'refs/heads/main' },
});
const res = await POST(req);
expect(res.status).toBe(200);
```

## Options

| Option | Description |
| :--- | :--- |
| `secret` | Signing secret, as you pass it to `verifyWebhook()`. Not needed for Discord and SendGrid, which use key pairs. |
| `payload` | Object (serialized as JSON) or exact string body. Default `{}`. |
| `form` | Form fields sent as `application/x-www-form-urlencoded` (Slack, Twilio). |
| `url` | Public URL signed by Twilio, Square and HubSpot. Default `https://example.com/webhooks/<provider>`. |
| `timestamp` | Unix seconds. Default now. Combine with `options.now` for fixed fixtures. |
| `webhookId` | `svix-id` for Svix, Resend and Clerk. |
| `event` | `x-github-event` for GitHub. Default `ping`. |
| `privateKey` | Discord: 32-byte Ed25519 seed (hex). Omitted: a key pair is generated and the public key is returned as `secret`. |
| `headerName`, `algorithm`, `encoding` | Generic provider settings. |
| `headers` | Extra headers to send (e.g. `x-shopify-topic`). |

The result is `{ provider, method, url, headers, body, secret }`.

## Fixed fixtures

Signed requests expire after the provider's replay window. To keep a saved fixture valid, sign it with a fixed `timestamp` and verify with the same `options.now`:

```ts
const hook = await signWebhook('slack', { secret, payload, timestamp: 1700000000 });
const result = await verifyWebhook('slack', hook, secret, { now: 1700000000 });
```

## From the command line

`npx verihook simulate` sends a signed webhook to a running server:

```sh
npx verihook simulate stripe --url http://localhost:3000/webhooks/stripe
npx verihook simulate github --event issues --secret my_secret
npx verihook simulate stripe --curl   # print a curl command instead
```

See [CLI](../cli/) for `simulate` and the `listen` relay.
