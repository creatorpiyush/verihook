---
title: Typed events
description: Get the parsed, typed webhook payload and event name from a verified request with result.event and result.eventType.
sidebar:
  order: 4
---

A successful result carries the parsed payload, so you don't parse the body yourself and never act on an unverified one:

- `result.event`: the parsed JSON body, or the form fields of a form post (Twilio, Slack slash commands). It's set only when `valid` is `true`.
- `result.eventType`: the event name, read from wherever the provider puts it (a body field or a header). Each [provider page](../../providers/) says where.

```ts
import { verifyGitHub } from 'verihook/github';

const result = await verifyGitHub(request, secret);
if (result.valid && result.eventType === 'issues') {
  console.log(result.event?.action, result.event?.repository?.full_name);
}
```

## Built-in types

Every provider has a lightweight event type (`StripeEvent`, `GitHubEvent`, `SvixEvent`, ...) covering its envelope: IDs, type names and the main data fields. They need no provider SDK.

```ts
import type { StripeEvent } from 'verihook';
```

## Your own type

Pass a type argument for a precise shape, for example the official SDK's type:

```ts
import type Stripe from 'stripe';

const result = await verifyWebhook<Stripe.Event>('stripe', request, secret);
// result.event is Stripe.Event | undefined
```

The shortcuts (`verifyStripe<T>()`) and the adapters (`createWebhookHandler<T>()`, `VerihookRequestAdditions<T>`) take a type argument too. The type isn't checked at runtime: validate untrusted fields as you would any input.
