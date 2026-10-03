---
title: Options
description: Every option accepted by verifyWebhook, the provider shortcuts and the framework adapters.
sidebar:
  order: 1
---

`verifyWebhook(provider, request, secret, options?)`, the shortcuts (`verifyStripe`, ...) and every adapter accept these options.

| Option | Default | Description |
| :--- | :--- | :--- |
| `tolerance` | `300` | Maximum age of the provider's timestamp, in seconds (180 for Calendly, 600 for Twitch). |
| `now` | current time | Unix seconds to check timestamps against. Useful for fixed test fixtures. |
| `url` | from the request | Public URL, for providers that sign it (Twilio, Square, HubSpot). Set it behind proxies that rewrite the host or path. |
| `webhookId` | | PayPal webhook ID. |
| `dedupeStore` | | Rejects repeated events with `DUPLICATE_EVENT`. See [Deduplication](../../guides/dedupe/). |
| `dedupeTtlMs` | `300000` | How long a dedupe key is remembered, in milliseconds. |
| `eventId` | extracted | Overrides the dedupe key. |
| `maxBodySize` | 2 MB | Largest body an adapter reads, in bytes. Larger bodies get `413`. |
| `onVerify` / `log` | | Called after every verification with a telemetry event. |
| `headerName` | | `generic` only: the signature header. |
| `algorithm` | `sha256` | `generic` only: `sha256`, `sha1` or `sha512`. |
| `encoding` | `hex` | `generic` only: `hex`, `base64` or `prefix-hex`. |

Adapters also take `onError` (`exceptionFactory` for NestJS) to replace the default failure response.

## The result

```ts
interface VerificationResult<TEvent> {
  valid: boolean;
  provider: string;
  code?: WebhookErrorCode;   // set when valid is false
  reason?: string;           // what failed
  hint?: string;             // likely cause and fix
  event?: TEvent;            // parsed payload, only when valid
  eventType?: string;        // event name
  timestamp?: number;        // provider timestamp, when there is one
  dedupeKey?: string;        // key recorded in the dedupe store
  error?: Error;             // original error for UNKNOWN_ERROR
}
```

## Strict mode

`verifyWebhookOrThrow` throws a `WebhookVerificationError` (with `provider`, `code`, `reason` and `hint`) instead of returning `valid: false`:

```ts
import { verifyWebhookOrThrow, WebhookVerificationError } from 'verihook';

try {
  const { event } = await verifyWebhookOrThrow('github', request, secret);
} catch (err) {
  if (err instanceof WebhookVerificationError) {
    console.error(err.code, err.reason);
  }
}
```

## Telemetry

Every verification can be reported to your logger or metrics, per call with `onVerify`, or for all calls:

```ts
import { setGlobalLogger } from 'verihook';

setGlobalLogger((event) => {
  metrics.increment('webhook.verified', { provider: event.provider, valid: String(event.valid), code: event.code });
});
```

Telemetry events include the provider, result, code, reason, hint, event type and duration. They never include the secret or the body.
