---
title: Remix / React Router
description: Verify webhook signatures in Remix and React Router v7 actions with verihook.
sidebar:
  order: 8
---

```ts
// app/routes/webhooks.github.ts
import { createWebhookHandler } from 'verihook/remix';

export const action = createWebhookHandler('github', process.env.GITHUB_WEBHOOK_SECRET!, async (payload, result, args) => {
  console.log(result.eventType);
});
```

The handler receives the action's arguments (`request`, `params`, `context`). It works with Remix and React Router v7 framework mode. Webhook routes have no `loader`, so GET requests get React Router's default 405.

`onError(result, args)` returns your own `Response` for failures.

## What the adapter does

| Situation | Response |
| :--- | :--- |
| Invalid, missing or expired signature | `401 { error, code }`, unless you pass `onError` |
| Duplicate event (with `dedupeStore`) | `200 { received: true, duplicate: true }` |
| Body over `maxBodySize` (default 2 MB) | `413 { code: "PAYLOAD_TOO_LARGE" }` |
| Exception during verification | `500` with a generic message |
| Your handler throws or responds `>= 500` | The dedupe key is released so the retry is processed |

All [verification options](../../reference/options/) (`tolerance`, `dedupeStore`, `url`, ...) can be passed as the last argument. Pick your provider in [Providers](../../providers/) for the secret and the headers it sends.
