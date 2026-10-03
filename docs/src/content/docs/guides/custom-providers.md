---
title: Custom providers
description: Verify webhooks from any service with verihook's generic HMAC verifier, or register your own provider.
sidebar:
  order: 5
---

## Generic HMAC

Most services sign the raw body with an HMAC and put the digest in a header. The `generic` provider handles that without code:

```ts
await verifyWebhook('generic', request, secret, {
  headerName: 'x-custom-signature',
  algorithm: 'sha256',  // 'sha256' | 'sha1' | 'sha512'
  encoding: 'hex',      // 'hex' | 'base64' | 'prefix-hex' (e.g. "sha256=<hex>")
});
```

## Register a provider

For other schemes (timestamps, signed URLs, key pairs), register a verifier. It receives the normalized request (lower-case headers, raw body as a string):

```ts
import { registerProvider, verifyWebhook, computeHmacSha256, bytesToHex, timingSafeEqual } from 'verihook';

registerProvider({
  name: 'my-service',
  async verify(req, secret) {
    const signature = req.headers['x-myservice-signature'];
    if (!signature) {
      return { valid: false, provider: 'my-service', code: 'MISSING_HEADER', reason: 'Missing signature' };
    }
    const expected = bytesToHex(await computeHmacSha256(secret, req.rawBody));
    return timingSafeEqual(expected, signature)
      ? { valid: true, provider: 'my-service' }
      : { valid: false, provider: 'my-service', code: 'INVALID_SIGNATURE', reason: 'Signature mismatch' };
  },
  // Optional: where result.eventType comes from
  eventType: (event, req) => req.headers['x-myservice-event'],
});

await verifyWebhook('my-service', request, secret);
```

Registered providers get the same pipeline as built-in ones: typed events, hints, telemetry and dedupe. Always compare signatures with `timingSafeEqual`.

## Contribute it

If the service is public, consider adding it to verihook. [CONTRIBUTING.md](https://github.com/creatorpiyush/verihook/blob/main/CONTRIBUTING.md) walks through adding a provider in five steps.
