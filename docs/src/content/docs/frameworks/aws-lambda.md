---
title: AWS Lambda
description: Verify webhook signatures in AWS Lambda behind API Gateway (REST v1, HTTP API v2) or Function URLs.
sidebar:
  order: 10
---

```ts
import { createWebhookHandler } from 'verihook/lambda';

export const handler = createWebhookHandler('stripe', process.env.STRIPE_WEBHOOK_SECRET!, async (payload, result, event, context) => {
  // return nothing for 200 { received: true }, or your own { statusCode, headers, body }
});
```

It accepts API Gateway REST (v1) and HTTP API (v2) events and Function URL events. Base64 bodies are decoded before verification.

For providers that sign the URL (Twilio, Square, HubSpot), the URL is rebuilt from the `Host` header and the request path, including the stage. Behind a custom domain with a base-path mapping, pass `{ url }`.

`MemoryDedupeStore` lives as long as one Lambda instance. Use [a shared store](../../guides/dedupe/#shared-stores) such as DynamoDB or Redis.

`onError(result, event)` returns your own result for failures.

## What the adapter does

| Situation | Response |
| :--- | :--- |
| Invalid, missing or expired signature | `401 { error, code }`, unless you pass `onError` |
| Duplicate event (with `dedupeStore`) | `200 { received: true, duplicate: true }` |
| Body over `maxBodySize` (default 2 MB) | `413 { code: "PAYLOAD_TOO_LARGE" }` |
| Exception during verification | `500` with a generic message |
| Your handler throws or responds `>= 500` | The dedupe key is released so the retry is processed |

All [verification options](../../reference/options/) (`tolerance`, `dedupeStore`, `url`, ...) can be passed as the last argument. Pick your provider in [Providers](../../providers/) for the secret and the headers it sends.
