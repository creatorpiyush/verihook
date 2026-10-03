/**
 * Lightweight payload types for the built-in providers. They describe the stable
 * envelope of each provider's webhook (event name, IDs, timestamps) and leave
 * provider objects loosely typed, so verihook needs no provider SDKs. Every type
 * keeps an index signature for fields that are not listed.
 *
 * For a precise shape, pass your own type: `verifyWebhook<Stripe.Event>("stripe", ...)`.
 */

type Fields = Record<string, unknown>;

export interface StripeEvent {
  id: string;
  object: "event";
  type: string;
  api_version: string | null;
  created: number;
  livemode: boolean;
  pending_webhooks: number;
  request: { id: string | null; idempotency_key: string | null } | null;
  data: {
    object: Fields & { id?: string; object?: string };
    previous_attributes?: Fields;
  };
  [key: string]: unknown;
}

/** GitHub sends the event name in `x-github-event` (see `result.eventType`). */
export interface GitHubEvent {
  action?: string;
  sender?: Fields & { login: string; id: number };
  repository?: Fields & { id: number; name: string; full_name: string };
  organization?: Fields & { login: string; id: number };
  installation?: Fields & { id: number };
  [key: string]: unknown;
}

/** Shopify sends the resource itself; the topic is in `x-shopify-topic` (see `result.eventType`). */
export interface ShopifyEvent {
  id?: number;
  admin_graphql_api_id?: string;
  [key: string]: unknown;
}

/** Slack Events API JSON, or the fields of a slash command / interactivity form post. */
export interface SlackEvent {
  type?: string;
  token?: string;
  challenge?: string;
  team_id?: string;
  api_app_id?: string;
  event?: Fields & { type: string };
  event_id?: string;
  event_time?: number;
  /** Slash commands (form post). */
  command?: string;
  /** Interactivity (form post): JSON string of the interaction payload. */
  payload?: string;
  [key: string]: unknown;
}

/** Twilio form parameters, e.g. `MessageSid`, `From`, `Body`, `CallStatus`. */
export type TwilioEvent = Record<string, string>;

/** Svix-delivered events (Svix, Resend, Clerk). */
export interface SvixEvent {
  type: string;
  data: Fields;
  [key: string]: unknown;
}

export interface LinearEvent {
  action: string;
  type: string;
  data: Fields;
  url?: string;
  createdAt: string;
  organizationId?: string;
  webhookTimestamp: number;
  webhookId?: string;
  [key: string]: unknown;
}

export interface RazorpayEvent {
  entity: "event";
  account_id: string;
  event: string;
  contains: string[];
  payload: Record<string, { entity: Fields }>;
  created_at: number;
  [key: string]: unknown;
}

export interface SquareEvent {
  merchant_id: string;
  type: string;
  event_id: string;
  created_at: string;
  data: { type: string; id: string; object?: Fields };
  [key: string]: unknown;
}

export interface ZoomEvent {
  event: string;
  event_ts: number;
  payload: Fields;
  [key: string]: unknown;
}

/** Meta Graph API webhooks (WhatsApp, Facebook, Instagram). */
export interface MetaEvent {
  object: string;
  entry: Array<
    Fields & {
      id: string;
      time?: number;
      changes?: Array<{ field: string; value: unknown }>;
      messaging?: unknown[];
    }
  >;
  [key: string]: unknown;
}

/** Discord interaction, or a webhook event (`event.type`, e.g. `APPLICATION_AUTHORIZED`). */
export interface DiscordEvent {
  type: number;
  id?: string;
  application_id: string;
  token?: string;
  version?: number;
  data?: Fields;
  event?: Fields & { type: string; timestamp?: string; data?: unknown };
  [key: string]: unknown;
}

/** Twitter/X Account Activity API, e.g. `tweet_create_events`. */
export interface TwitterEvent {
  for_user_id?: string;
  user_has_blocked?: boolean;
  [key: string]: unknown;
}

export interface PayPalEvent {
  id: string;
  event_version: string;
  create_time: string;
  resource_type: string;
  event_type: string;
  summary?: string;
  resource: Fields;
  [key: string]: unknown;
}

export interface LemonSqueezyEvent {
  meta: Fields & {
    event_name: string;
    custom_data?: Fields;
    test_mode?: boolean;
    webhook_id?: string;
  };
  data: Fields & { type: string; id: string; attributes: Fields };
  [key: string]: unknown;
}

export interface PaddleEvent {
  event_id: string;
  event_type: string;
  occurred_at: string;
  notification_id: string;
  data: Fields;
  [key: string]: unknown;
}

export interface PagerDutyEvent {
  event: Fields & {
    id: string;
    event_type: string;
    resource_type: string;
    occurred_at: string;
    data: Fields;
  };
  [key: string]: unknown;
}

export interface WebflowEvent {
  triggerType: string;
  payload: Fields;
  [key: string]: unknown;
}

export interface WorkOSEvent {
  id: string;
  event: string;
  data: Fields;
  created_at: string;
  [key: string]: unknown;
}

/** Cashfree Payments, e.g. `PAYMENT_SUCCESS_WEBHOOK`. */
export interface CashfreeEvent {
  type: string;
  event_time: string;
  data: Fields;
  [key: string]: unknown;
}

/** PhonePe Payment Gateway, e.g. `checkout.order.completed`. Ignore the deprecated `type`. */
export interface PhonePeEvent {
  event: string;
  type?: string;
  payload: Fields;
  [key: string]: unknown;
}

/** Mollie next-gen webhook event, e.g. `payment-link.paid`. */
export interface MollieEvent {
  resource: "event";
  id: string;
  type: string;
  entityId: string;
  createdAt: string;
  _embedded?: Fields;
  _links?: Fields;
  [key: string]: unknown;
}

export interface AdyenNotificationRequestItem {
  eventCode: string;
  success: "true" | "false";
  pspReference: string;
  originalReference?: string;
  merchantAccountCode: string;
  merchantReference: string;
  amount?: { value: number; currency: string };
  eventDate?: string;
  additionalData?: Fields & { hmacSignature?: string };
  [key: string]: unknown;
}

/**
 * Adyen standard notification (`notificationItems`, event in `eventCode`), or a
 * platform/management webhook (`type`, `data`).
 */
export interface AdyenEvent {
  live?: string;
  notificationItems?: Array<{
    NotificationRequestItem: AdyenNotificationRequestItem;
  }>;
  type?: string;
  data?: Fields;
  [key: string]: unknown;
}

/** Checkout.com, e.g. `payment_approved`. */
export interface CheckoutEvent {
  id: string;
  type: string;
  version?: string;
  created_on: string;
  data: Fields;
  _links?: Fields;
  [key: string]: unknown;
}

/** Authorize.net, e.g. `net.authorize.payment.authcapture.created`. */
export interface AuthorizeNetEvent {
  notificationId: string;
  eventType: string;
  eventDate: string;
  webhookId: string;
  payload: Fields;
  [key: string]: unknown;
}

/** Recurly JSON webhook; `result.eventType` is `<object_type>.<event_type>`. */
export interface RecurlyEvent {
  id: string;
  object_type: string;
  site_id: string;
  event_type: string;
  event_time: string;
  account_code?: string;
  uuid?: string;
  [key: string]: unknown;
}

/** Payload type for each built-in provider identifier. */
export interface ProviderEventMap {
  stripe: StripeEvent;
  github: GitHubEvent;
  shopify: ShopifyEvent;
  slack: SlackEvent;
  twilio: TwilioEvent;
  svix: SvixEvent;
  resend: SvixEvent;
  clerk: SvixEvent;
  linear: LinearEvent;
  razorpay: RazorpayEvent;
  square: SquareEvent;
  zoom: ZoomEvent;
  meta: MetaEvent;
  whatsapp: MetaEvent;
  facebook: MetaEvent;
  instagram: MetaEvent;
  discord: DiscordEvent;
  twitter: TwitterEvent;
  x: TwitterEvent;
  paypal: PayPalEvent;
  lemonsqueezy: LemonSqueezyEvent;
  paddle: PaddleEvent;
  pagerduty: PagerDutyEvent;
  webflow: WebflowEvent;
  workos: WorkOSEvent;
  cashfree: CashfreeEvent;
  phonepe: PhonePeEvent;
  mollie: MollieEvent;
  adyen: AdyenEvent;
  checkout: CheckoutEvent;
  authorizenet: AuthorizeNetEvent;
  recurly: RecurlyEvent;
  generic: unknown;
}

/** Payload type of provider `P`; `unknown` for custom providers. */
export type EventFor<P> = P extends keyof ProviderEventMap
  ? ProviderEventMap[P]
  : unknown;

/** An explicit event type wins; otherwise the provider's built-in type. */
export type ResolveEvent<TEvent, P> = [TEvent] extends [never]
  ? EventFor<P>
  : TEvent;
