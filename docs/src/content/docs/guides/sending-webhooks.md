---
title: Sending webhooks
description: Sign and send webhooks to your customers with verihook/send, using the Standard Webhooks scheme that verihook, Svix and other libraries verify.
sidebar:
  order: 9
---

`verihook/send` is for the other side: your app **sends** webhooks and your customers verify them. Requests are signed with [Standard Webhooks](https://www.standardwebhooks.com), the scheme Svix created, so receivers can verify them with `verifyWebhook('standard-webhooks', ...)`, Svix's libraries or any Standard Webhooks implementation.

```ts
import { generateWebhookSecret, sendWebhook } from 'verihook/send';

// Once, when a customer adds an endpoint: store it and show it to them.
const secret = generateWebhookSecret(); // whsec_...

const result = await sendWebhook(endpoint.url, {
  secret: endpoint.secret,
  payload: { type: 'invoice.paid', data: { id: 'inv_123' } },
});

if (!result.ok) {
  console.warn('delivery failed', result.status, result.error?.message);
}
```

Each request carries `webhook-id`, `webhook-timestamp` and `webhook-signature: v1,<base64 HMAC-SHA256 of id.timestamp.body>`.

## What `sendWebhook` does, and doesn't

- **One attempt.** It never throws for a delivery failure (blocked URL, network error, timeout, non-2xx); check `result.ok`. Retries are yours, from your job queue.
- **Times out** after `timeoutMs` (10 s by default).
- **Doesn't follow redirects**, so a receiver can't bounce the request to another host. A 3xx is a failure with `result.error`.
- **Refuses non-public hosts**: loopback, private networks, link-local and cloud metadata addresses (`169.254.169.254`, ...), however they're written. `allowPrivateNetworks: true` turns this off for local development.

:::caution
The host check sees the URL, not DNS. A public hostname that resolves to a private address is not caught. When endpoint URLs come from your customers, send through an egress proxy that blocks private ranges, or pass your own `fetch` (`options.fetch`) bound to an agent that does.
:::

## Retries

Reuse `result.id` when retrying the same event, so receivers deduplicate it (verihook's dedupe store keys on `webhook-id`). A minimal retry loop:

```ts
import { sendWebhook, type SendWebhookOptions } from 'verihook/send';

async function deliver(url: string, options: SendWebhookOptions) {
  let id = options.id;
  for (const delayMs of [0, 5_000, 30_000, 300_000]) {
    await new Promise((r) => setTimeout(r, delayMs));
    const result = await sendWebhook(url, { ...options, id });
    if (result.ok) return result;
    id = result.id; // same message ID on every attempt
    if (result.status && result.status >= 400 && result.status < 500 && result.status !== 429) {
      return result; // the receiver rejected it; retrying won't help
    }
  }
}
```

In production, run retries from a durable queue rather than in memory.

## Rotating a customer's secret

Pass both secrets while the customer switches over. The request carries one signature per secret, and the receiver accepts any match:

```ts
await sendWebhook(endpoint.url, { secret: [endpoint.newSecret, endpoint.oldSecret], payload });
```

## Signing without sending

`signOutgoingWebhook` returns `{ id, timestamp, body, headers }` with no I/O, for when you send with your own HTTP client or queue:

```ts
import { signOutgoingWebhook } from 'verihook/send';

const { headers, body } = await signOutgoingWebhook({ secret, payload });
await myQueue.publish({ url, headers, body });
```

## Verifying, on the receiving side

```ts
import { verifyStandardWebhooks } from 'verihook/standard-webhooks';

const result = await verifyStandardWebhooks(request, process.env.WEBHOOK_SECRET!);
```

See the [Standard Webhooks provider page](../../providers/standard-webhooks/).
