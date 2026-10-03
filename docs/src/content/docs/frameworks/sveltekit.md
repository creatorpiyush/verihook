---
title: SvelteKit
description: Verify webhook signatures in SvelteKit +server.ts endpoints with verihook.
sidebar:
  order: 7
---

```ts
// src/routes/webhooks/github/+server.ts
import { env } from '$env/dynamic/private';
import { createWebhookHandler } from 'verihook/sveltekit';

export const POST = createWebhookHandler('github', () => env.GITHUB_WEBHOOK_SECRET, async (payload, result, event) => {
  console.log(result.eventType); // "push", "issues", ...
});
```

The handler and a secret function receive SvelteKit's `RequestEvent`, so you can read `event.platform.env` on Cloudflare. Return a `Response` to override the default `200 { received: true }`.

`onError(result, event)` returns your own `Response` for failures.

## What the adapter does

| Situation | Response |
| :--- | :--- |
| Invalid, missing or expired signature | `401 { error, code }`, unless you pass `onError` |
| Duplicate event (with `dedupeStore`) | `200 { received: true, duplicate: true }` |
| Body over `maxBodySize` (default 2 MB) | `413 { code: "PAYLOAD_TOO_LARGE" }` |
| Exception during verification | `500` with a generic message |
| Your handler throws or responds `>= 500` | The dedupe key is released so the retry is processed |

All [verification options](../../reference/options/) (`tolerance`, `dedupeStore`, `url`, ...) can be passed as the last argument. Pick your provider in [Providers](../../providers/) for the secret and the headers it sends.
