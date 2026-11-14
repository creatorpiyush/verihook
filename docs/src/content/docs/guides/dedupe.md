---
title: Deduplication and replays
description: Reject duplicate and replayed webhook deliveries with verihook's dedupe store, in memory or in Redis, Upstash or Cloudflare KV.
sidebar:
  order: 3
---

Providers deliver at least once: a timeout or a 5xx makes them retry, so the same event can arrive several times. A signature check alone accepts every copy. A **dedupe store** remembers the events you've seen and rejects repeats with `DUPLICATE_EVENT`.

```ts
import { MemoryDedupeStore, verifyWebhook, WebhookErrorCode } from 'verihook';

const dedupeStore = new MemoryDedupeStore({ ttlMs: 86_400_000, maxSize: 10_000 });

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

## When the handler crashes

Releasing a key needs a live process. If yours is killed mid-handler (out of memory, a deploy, a Lambda timeout), nothing releases it, and a key recorded for 24 hours would make the provider's retry a "duplicate": the event would never be processed.

So the adapters record an event in two phases:

1. A new event is **claimed** for 60 seconds (`dedupeProcessingTtlMs`).
2. When your handler finishes with a response below 500, the key is **committed** for the full `dedupeTtlMs`.

A delivery that arrives while the first one is still claimed fails with `EVENT_IN_PROGRESS`, and the adapters answer `503` so the provider retries later. They don't answer `200`: if the first delivery then crashed, nothing would retry the event. If the process dies, the claim expires after 60 seconds and the next retry is processed.

This needs a store with `claim` and `commit`: `MemoryDedupeStore`, `RedisDedupeStore` and the reference stores have them. With any other store, or with `dedupeProcessingTtlMs: 0`, the adapters record the key once for the full TTL, as before.

Events are processed at least once, not exactly once: a handler that runs longer than `dedupeProcessingTtlMs` can overlap with a retry, so raise it for slow handlers and keep side effects idempotent. The AWS Lambda adapter does this for you: it holds the claim until the invocation's timeout (`context.getRemainingTimeInMillis()`) when that is longer than 60 seconds, since a handler can't outlive it.

Each claim belongs to one delivery (`result.dedupeToken`). If a slow delivery finishes after its claim expired and a retry took over, its commit or release is ignored, so it can't remove the retry's claim or a finished record.

`verifyWebhook` on its own can't know when your handler has finished, so it stays single-phase unless you opt in and commit yourself:

```ts
const options = { dedupeStore, dedupeProcessingTtlMs: 60_000 };
const result = await verifyWebhook('stripe', request, secret, options);

if (!result.valid) {
  if (result.code === WebhookErrorCode.DUPLICATE_EVENT) return Response.json({ received: true });
  if (result.code === WebhookErrorCode.EVENT_IN_PROGRESS) return new Response(null, { status: 503 });
  return new Response('Invalid signature', { status: 401 });
}

try {
  await processEvent(result.event);
} catch (err) {
  await dedupeStore.delete(result.dedupeKey!, result.dedupeToken);
  throw err;
}
await dedupeStore.commit(result.dedupeKey!, 86_400_000, result.dedupeToken);
```

Don't set `dedupeProcessingTtlMs` without calling `commit`: the key would expire after 60 seconds and a replay would verify again.

## How long to remember keys

Keys live for 24 hours by default (`dedupeTtlMs`). Many providers (GitHub, Shopify, Square, Twitter, ...) sign no timestamp, so the dedupe store is their only replay protection: once a key expires, a captured delivery verifies again. Keep the TTL at least as long as you care about replays, and size `MemoryDedupeStore`'s `maxSize` for a day of traffic, or use a shared store.

For these providers no TTL closes the window completely: a captured delivery stays validly signed forever. Treat the store as a fast filter, not a guarantee, and make the handler's side effects idempotent too, for example with a unique constraint on the event ID in your own database. Then a replay after the key expires can't charge, email or provision twice. Memory stores also forget keys on restart or eviction, so the same applies there.

## What the key is

The key only uses data covered by the provider's signature, so an attacker can't change it to sneak a replay past the store:

1. a signed ID header: `svix-id` (Svix, Resend, Clerk), `webhook-id` or `idempotency-key` (GitLab), `paypal-transmission-id`, `twitch-eventsub-message-id`;
2. Mailgun's signed `token`;
3. for Adyen standard webhooks, a SHA-256 of each item's signed fields (the rest of the body isn't signed);
4. an ID in the signed body: `id`, `event_id`, `msg_id`, `notificationId`, or a WhatsApp message ID;
5. otherwise a SHA-256 of the body.

Override it with `options.eventId` if you know better.

## Shared stores

`MemoryDedupeStore` lives in one process. Serverless functions and multiple replicas each have their own memory, so use a shared store.

### Redis

`RedisDedupeStore` works with the Redis client you already use (ioredis, node-redis v4+ or Bun's `RedisClient`); verihook adds no dependency.

```ts
import { Redis } from 'ioredis';
import { RedisDedupeStore, verifyWebhook } from 'verihook';

const dedupeStore = new RedisDedupeStore(new Redis(process.env.REDIS_URL!), {
  keyPrefix: 'myapp:webhooks:', // default: 'verihook:dedupe:'
});

const result = await verifyWebhook('stripe', request, secret, { dedupeStore });
```

With node-redis, connect first: `new RedisDedupeStore(await createClient({ url }).connect())`. With Bun: `new RedisDedupeStore(new RedisClient(url))`.

- Each event is recorded with one atomic `SET key <state> PX <ttl> NX`, so two instances receiving the same delivery at once can't both process it. The state is `p` while the event is being processed and `1` once committed (see [When the handler crashes](#when-the-handler-crashes)).
- `delete()` runs `DEL`, so the adapters release the key when your handler fails.
- If Redis is unreachable, verification fails (`UNKNOWN_ERROR`, a `500` from the adapters) and the provider retries. Events are never let through unchecked.

### Your own store

For anything else, implement the `DedupeStore` interface:

```ts
import type { DedupeStore } from 'verihook';

const store: DedupeStore = {
  // Returns true if the key was already seen; otherwise records it for ttlMs and returns false.
  async hasOrSet(key, ttlMs) { /* ... */ },
  // Optional: lets the adapters release a key when your handler fails.
  // With a token, delete only while the key is still claimed with that token.
  async delete(key, token) { /* ... */ },
  // Optional pair: two-phase recording, so a crashed handler's retry is processed.
  // Returns 'new' after recording the key as in progress for processingTtlMs,
  // owned by token; 'processing' if it is claimed but not committed; 'done' if
  // it is committed.
  async claim(key, processingTtlMs, token) { /* ... */ },
  // Marks the key as processed and keeps it for ttlMs. With a token, do nothing
  // if the key is claimed by another token or already committed; record a
  // missing key.
  async commit(key, ttlMs, token) { /* ... */ },
};
```

Make the token checks atomic where your store allows it (a Lua script in Redis, like `RedisDedupeStore`). Otherwise a slow delivery can, in a narrow race, remove a retry's claim.

Implement `delete` whenever you can: without it, a delivery whose handler failed is acked as a duplicate when the provider retries it, and the event is lost. Implement `claim` and `commit` too, so the same doesn't happen when the process dies mid-handler.

Ready-made examples are in the repository: [Upstash Redis](https://github.com/creatorpiyush/verihook/blob/main/examples/dedupe-stores/upstash-redis.ts) for edge runtimes and [Cloudflare Workers KV](https://github.com/creatorpiyush/verihook/blob/main/examples/dedupe-stores/cloudflare-kv.ts).

## Strict mode

Some providers have a stronger scheme and accept a weaker fallback, and the fallback can drop replay protection. HubSpot, for example, sends its old v1/v2 signature next to v3 for compatibility: a captured request with the v3 headers stripped still verifies through v1/v2, which has no timestamp. `strict: true` accepts only the strongest scheme:

```ts
const result = await verifyWebhook('hubspot', request, secret, { strict: true });
```

| Provider | Required in strict mode | Rejected with `WEAK_SCHEME` |
| :--- | :--- | :--- |
| HubSpot | v3 (`X-HubSpot-Signature-v3`) | v1 / v2 |
| GitLab | signing token (`webhook-signature`) | secret token (`X-Gitlab-Token`) |
| Webflow | `x-webflow-timestamp` | body-only signatures |
| Linear | `webhookTimestamp` in the body | bodies without it |
| GitHub, Meta | `x-hub-signature-256` | SHA-1 `x-hub-signature` alone |
| Paddle | `h1` | legacy `h` alone |
| Mailgun | a `dedupeStore` (the event data isn't signed, only the single-use `token`) | any request without one |

Other providers have a single scheme, so strict mode changes nothing for them: Telegram, Postmark and PhonePe authenticate with a static token, Twilio and Intercom with HMAC-SHA1.

## Which endpoints rely on dedupe alone

Valid results carry `timestampVerified`: `true` when a signed timestamp was checked against `tolerance`, `false` when nothing limits a replay. It is in the telemetry event too, so you can find the endpoints that need a dedupe store:

```ts
import { setGlobalLogger } from 'verihook';

setGlobalLogger((event) => {
  if (event.valid && !event.timestampVerified) metrics.increment('webhooks.no_replay_window', { provider: event.provider });
});
```
