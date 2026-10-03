// Compile-time checks for typed events (run by `npm run typecheck`).
import { expectTypeOf } from "vitest";
import {
  verifyStripe,
  verifyWebhook,
  verifyWebhookOrThrow,
  type GitHubEvent,
  type ProviderName,
  type StripeEvent,
  type TwilioEvent,
} from "../../src/index.js";
import { createWebhookHandler } from "../../src/next.js";

declare const req: Request;

interface MyEvent {
  kind: "custom";
}

export async function checks() {
  const stripe = await verifyWebhook("stripe", req, "whsec_x");
  expectTypeOf(stripe.event).toEqualTypeOf<StripeEvent | undefined>();
  expectTypeOf(stripe.eventType).toEqualTypeOf<string | undefined>();

  const github = await verifyWebhookOrThrow("github", req, "s");
  expectTypeOf(github.event).toEqualTypeOf<GitHubEvent | undefined>();

  const twilio = await verifyWebhook("twilio", req, "s");
  expectTypeOf(twilio.event).toEqualTypeOf<TwilioEvent | undefined>();

  // Explicit type argument overrides the built-in type.
  const custom = await verifyWebhook<MyEvent>("stripe", req, "whsec_x");
  expectTypeOf(custom.event).toEqualTypeOf<MyEvent | undefined>();

  const shortcut = await verifyStripe(req, "whsec_x");
  expectTypeOf(shortcut.event).toEqualTypeOf<StripeEvent | undefined>();
  const shortcutCustom = await verifyStripe<MyEvent>(req, "whsec_x");
  expectTypeOf(shortcutCustom.event).toEqualTypeOf<MyEvent | undefined>();

  // Custom providers and non-literal names stay unknown.
  const plugin = await verifyWebhook("my-service", req, "s");
  expectTypeOf(plugin.event).toEqualTypeOf<unknown>();
  const name: ProviderName = "stripe" as ProviderName;
  expectTypeOf(
    (await verifyWebhook(name, req, "s")).event,
  ).toEqualTypeOf<unknown>();

  createWebhookHandler("stripe", "whsec_x", (_payload, result) => {
    expectTypeOf(result.event).toEqualTypeOf<StripeEvent | undefined>();
  });
  createWebhookHandler<MyEvent>("stripe", "whsec_x", (_payload, result) => {
    expectTypeOf(result.event).toEqualTypeOf<MyEvent | undefined>();
  });
}
