---
title: Astro
description: Verify webhook signatures in Astro server endpoints with verihook.
sidebar:
  order: 9
---

```ts
// src/pages/api/webhooks/github.ts
import { createWebhookHandler } from 'verihook/astro';

export const prerender = false;

export const POST = createWebhookHandler('github', import.meta.env.GITHUB_WEBHOOK_SECRET, async (payload, result, context) => {
  console.log(result.eventType);
});
```

Endpoints must be server-rendered: set `prerender = false` (or `output: 'server'`) and use an adapter. On Cloudflare, read secrets from `context.locals.runtime.env` with a secret function.

`onError(result, context)` returns your own `Response` for failures.

## What the adapter does

| Situation | Response |
| :--- | :--- |
| Invalid, missing or expired signature | `401 { error, code }`, unless you pass `onError` |
| Duplicate event (with `dedupeStore`) | `200 { received: true, duplicate: true }` |
| Body over `maxBodySize` (default 2 MB) | `413 { code: "PAYLOAD_TOO_LARGE" }` |
| Exception during verification | `500` with a generic message |
| Your handler throws or responds `>= 500` | The dedupe key is released so the retry is processed |

All [verification options](../../reference/options/) (`tolerance`, `dedupeStore`, `url`, ...) can be passed as the last argument. Pick your provider in [Providers](../../providers/) for the secret and the headers it sends.
