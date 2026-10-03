---
title: Deduplication and replays
description: Reject duplicate and replayed webhook deliveries with verihook's dedupe store, in memory or in Redis, Upstash or Cloudflare KV.
sidebar:
  order: 3
---

Providers deliver at least once: a timeout or a 5xx makes them retry, so the same event can arrive several times. A signature check alone accepts every copy. A **dedupe store** remembers the events you've seen and rejects repeats with `DUPLICATE_EVENT`.

```ts
import { MemoryDedupeStore, verifyWebhook, WebhookErrorCode } from 'verihook';

const dedupeStore = new MemoryDedupeStore({ ttlMs: 300_000, maxSize: 10_000 });

const result = await verifyWebhook('stripe', request, secret, { dedupeStore });

if (!result.valid && result.code === WebhookErrorCode.DUPLICATE_EVENT) {
  return Response.json({ received: true, duplicate: true }); // 2xx stops retries
}

try {
  await processEvent(result.event);
} catch (err) {
  await dedupeStore.delete(result.dedupeKey!); // let the retry through
  throw err;
}
```

The adapters do both for you: duplicates get `200`, and if your handler throws or responds with a 5xx the key is released so the provider's retry is processed.

## What the key is

The key only uses data covered by the provider's signature, so an attacker can't change it to sneak a replay past the store:

1. a signed ID header: `svix-id` (Svix, Resend, Clerk), `webhook-id` or `idempotency-key` (GitLab), `paypal-transmission-id`, `twitch-eventsub-message-id`;
2. Mailgun's signed `token`;
3. an ID in the signed body: `id`, `event_id`, `msg_id`, `notificationId`, or a WhatsApp message ID;
4. otherwise a SHA-256 of the body.

Override it with `options.eventId` if you know better.

## Shared stores

`MemoryDedupeStore` lives in one process. Serverless functions and multiple replicas each have their own memory, so use a shared store. Implement the `DedupeStore` interface:

```ts
import type { DedupeStore } from 'verihook';

const store: DedupeStore = {
  // Returns true if the key was already seen; otherwise records it for ttlMs and returns false.
  async hasOrSet(key, ttlMs) { /* ... */ },
  // Optional: lets the adapters release a key when your handler fails.
  async delete(key) { /* ... */ },
};
```

Ready-made examples are in the repository: [Upstash Redis](https://github.com/creatorpiyush/verihook/blob/main/examples/dedupe-stores/upstash-redis.ts) for edge runtimes and [Cloudflare Workers KV](https://github.com/creatorpiyush/verihook/blob/main/examples/dedupe-stores/cloudflare-kv.ts).
