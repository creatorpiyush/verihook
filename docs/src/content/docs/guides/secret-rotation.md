---
title: Rotating secrets
description: Rotate a webhook signing secret without downtime by passing both the new and the old secret to verihook.
sidebar:
  order: 4
---

Pass an array instead of a single secret. A request is valid if **any** secret matches, tried in order, so deliveries signed with the old secret keep working while the provider switches over.

```ts
import { verifyWebhook } from 'verihook';

const result = await verifyWebhook('stripe', request, [
  process.env.STRIPE_WEBHOOK_SECRET!,     // new
  process.env.STRIPE_WEBHOOK_SECRET_OLD!, // old, remove once the rotation ends
]);
```

Arrays work everywhere a secret does: `verifyWebhook`, `verifyWebhookOrThrow`, the provider shortcuts (`verifyStripe`, `verihook/stripe`, ...) and every adapter. A secret resolver may return one too:

```ts
import { verihookHono } from 'verihook/hono';

app.post('/webhooks/github', verihookHono('github', (c) => [c.env.GITHUB_SECRET, c.env.GITHUB_SECRET_OLD]));
```

- Empty entries are skipped, so an unset `*_OLD` variable is harmless. If every entry is empty, verification fails with `INVALID_SECRET`.
- If no secret matches, the result is the first secret's failure (`code`, `reason`, `hint`). Put the current secret first.
- Each extra secret costs one more HMAC, and only when the earlier ones fail.

## A rotation, step by step

1. Add the new secret first in the list and deploy: `[NEW, OLD]`.
2. Rotate the secret in the provider's dashboard. Many providers switch to the new secret at once, so both must already be accepted when you rotate.
3. Once no delivery is signed with the old secret any more (wait out the provider's retry window), remove it: `[NEW]` or just `NEW`.

Stripe and Mollie send one signature per active secret while they roll a secret, and verihook checks all of them, so a single secret already works there. The array is for the providers that don't, and for your side of the switch.
