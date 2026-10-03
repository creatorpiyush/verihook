---
title: Troubleshooting
description: What each verihook error code means, the usual causes and how to fix them.
sidebar:
  order: 3
---

A failed verification returns `valid: false` with three fields:

- `code`: one of the error codes below;
- `reason`: what failed, in words;
- `hint`: the likely cause and fix, when verihook can tell.

```ts
const result = await verifyWebhook('stripe', request, secret);
if (!result.valid) {
  logger.warn({ code: result.code, reason: result.reason, hint: result.hint });
}
```

Log hints, but don't send them back in HTTP responses: they describe your configuration. Outside production and tests, verihook prints each distinct hint once with `console.warn`.

## INVALID_SIGNATURE

The signature doesn't match the body and secret. In order of likelihood:

1. **The body was parsed before verification.** `express.json()`, `bodyParser`, Fastify's default parser or `await request.json()` produce an object; re-serializing it changes the bytes. Verify the raw body instead (see [Why the raw body matters](../guides/raw-body/)). The hint says so when the body length doesn't match `content-length`.
2. **Wrong secret.** Common mix-ups:
   - a Stripe API key (`sk_...`) instead of the endpoint's signing secret (`whsec_...`);
   - the test-mode secret in production, or another endpoint's secret;
   - a Slack bot token instead of the signing secret;
   - a secret with stray whitespace or quotes from your `.env` file.
3. **The URL differs from what the provider signed.** Twilio, Square and HubSpot sign the public URL. Behind a proxy, tunnel or API gateway the server sees another URL. Forward `x-forwarded-proto` and `x-forwarded-host`, or pass `{ url: 'https://public.example.com/webhooks/twilio' }`.
4. **Wrong provider.** The hint names the provider whose headers the request has.

## MISSING_HEADER

A header the provider always sends isn't there.

- The request may not come from the provider (a health check, a browser, a scan).
- The endpoint may be verifying the wrong provider. The hint names the provider whose signature header was found.
- A proxy or CDN may be stripping headers. Check what reaches your server.
- No headers were passed at all. Pass `request.headers` or `req.headers` with the body.

## EXPIRED_TIMESTAMP

The provider's timestamp is outside the replay window (300 seconds by default; 180 for Calendly, 600 for Twitch).

- Replaying a saved request in tests? Pass `options.now` with the time it was signed, or sign a fresh one with [`verihook/testing`](../guides/testing/).
- Check the server clock. Containers and VMs can drift.
- To accept older deliveries, raise `options.tolerance` (seconds), keeping in mind it widens the replay window.

## INVALID_BODY

A plain object was passed as the body. verihook needs the raw string or bytes to recompute the signature. Pass `rawBody` or use an adapter.

## INVALID_SECRET

The secret is empty or missing, usually an unset environment variable. Check that it's set in the environment where the code runs (production, preview, the worker's bindings).

## MISSING_URL

The provider signs the URL (Twilio, Square, HubSpot) and verihook couldn't build it. Pass a Fetch `Request`, an absolute `url`, or `options.url`.

## DUPLICATE_EVENT

A `dedupeStore` has already seen this event within its TTL. This is expected when providers retry. Respond `2xx` so the provider stops; the adapters respond `200 { received: true, duplicate: true }`. See [Deduplication](../guides/dedupe/).

## UNSUPPORTED_PROVIDER

The identifier isn't built in or registered. Check the spelling against [All providers](../providers/) or [register a custom provider](../guides/custom-providers/).

## UNKNOWN_ERROR

Something threw during verification, such as malformed key material or a failed PayPal certificate download. The original error is in `result.error`; adapters respond `500` without details.

## Adapter responses

| Situation | Response |
| :--- | :--- |
| Invalid, missing or expired signature | `401 { error, code }` unless you pass `onError` |
| Duplicate event | `200 { received: true, duplicate: true }` |
| Body larger than `maxBodySize` (2 MB) | `413 { code: "PAYLOAD_TOO_LARGE" }` |
| Exception during verification | `500` with a generic message |
