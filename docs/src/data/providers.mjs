/**
 * Provider data for the generated pages in src/content/docs/providers/.
 * Run `npm run generate` after editing. Markdown is allowed in `secret`, `notes`
 * and `handshake`.
 *
 * Fields:
 *   id         verihook identifier (`verifyWebhook("<id>", ...)`)
 *   name       display name
 *   aliases    other identifiers that share the verifier
 *   fn         shortcut function exported by `verihook` and the provider subpath
 *   entry      provider subpath (`verihook/<entry>`)
 *   env        environment variable used in the snippets
 *   headers    headers the provider sends
 *   scheme     how the signature is computed
 *   secret     what to pass as the secret and where to find it
 *   tolerance  replay window, when the provider sends a timestamp
 *   eventType  where `result.eventType` comes from
 *   notes      gotchas
 *   handshake  extra request the provider sends during setup
 *   signable   whether `verihook/testing` can sign it (default true)
 *   testSecret secret used in the testing snippet
 *   docs       the provider's own documentation
 */
export const providers = [
  {
    id: "stripe",
    name: "Stripe",
    fn: "verifyStripe",
    entry: "stripe",
    env: "STRIPE_WEBHOOK_SECRET",
    headers: ["stripe-signature"],
    scheme:
      "HMAC-SHA256 of `<timestamp>.<raw body>`, sent as `t=<timestamp>,v1=<hex>`.",
    secret:
      "The endpoint's **signing secret** (`whsec_...`). In the Stripe Dashboard, open **Developers → Webhooks**, select the endpoint and reveal the signing secret. When you forward events with `stripe listen`, use the `whsec_...` value the CLI prints instead.",
    tolerance: "300 seconds",
    eventType: "the body's `type`, e.g. `payment_intent.succeeded`",
    notes: [
      "Each endpoint has its own signing secret, and test mode and live mode secrets differ.",
      "A Stripe API key (`sk_...`, `rk_...`) is not a webhook secret. verihook's `result.hint` points this out.",
      "Pass `Stripe.Event` as a type argument (`verifyStripe<Stripe.Event>(...)`) for the official SDK's types.",
    ],
    testSecret: "whsec_test_secret",
    docs: "https://docs.stripe.com/webhooks#verify-events",
  },
  {
    id: "github",
    name: "GitHub",
    fn: "verifyGitHub",
    entry: "github",
    env: "GITHUB_WEBHOOK_SECRET",
    headers: ["x-hub-signature-256", "x-hub-signature (SHA-1, legacy)", "x-github-event", "x-github-delivery"],
    scheme: "HMAC-SHA256 of the raw body, sent as `sha256=<hex>`.",
    secret:
      "The **secret** you typed when creating the webhook: **Settings → Webhooks** on the repository or organization, or the webhook secret of your GitHub App. GitHub never shows it again, so set a new one if you lost it.",
    eventType: "the `x-github-event` header, e.g. `push` or `issues`",
    notes: [
      "GitHub sends a `ping` event when you create the webhook. Return 2xx for it.",
      "GitHub doesn't sign the `x-github-delivery` header, so a dedupe store keys GitHub events on a SHA-256 of the signed body instead. A redelivered event has the same body and is detected as a duplicate.",
    ],
    testSecret: "github_test_secret",
    docs: "https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries",
  },
  {
    id: "shopify",
    name: "Shopify",
    fn: "verifyShopify",
    entry: "shopify",
    env: "SHOPIFY_WEBHOOK_SECRET",
    headers: ["x-shopify-hmac-sha256", "x-shopify-topic", "x-shopify-webhook-id"],
    scheme: "HMAC-SHA256 of the raw body, base64-encoded.",
    secret:
      "For an app, the app's **client secret** (API secret key) from the Partner Dashboard or the Dev Dashboard. For webhooks created in the store admin under **Settings → Notifications → Webhooks**, the signing key shown on that page.",
    eventType: "the `x-shopify-topic` header, e.g. `orders/create`",
    notes: [
      "Rotating the app's client secret changes the webhook signature too. Deploy the new secret before rotating.",
    ],
    testSecret: "shopify_test_secret",
    docs: "https://shopify.dev/docs/apps/build/webhooks/subscribe/https",
  },
  {
    id: "slack",
    name: "Slack",
    fn: "verifySlack",
    entry: "slack",
    env: "SLACK_SIGNING_SECRET",
    headers: ["x-slack-signature", "x-slack-request-timestamp"],
    scheme: "HMAC-SHA256 of `v0:<timestamp>:<raw body>`, sent as `v0=<hex>`.",
    secret:
      "The app's **Signing Secret**: open your app at api.slack.com/apps, then **Basic Information → App Credentials**. It is not the bot token or the deprecated verification token.",
    tolerance: "300 seconds",
    eventType:
      "the body's `type` (Events API), the slash `command`, or the interaction `payload.type`",
    notes: [
      "Slash commands and interactivity are form posts (`application/x-www-form-urlencoded`). `result.event` holds the form fields; interactivity puts JSON in the `payload` field.",
      "The Events API sends a `url_verification` request when you set the URL. After verification, respond with the `challenge` value from the body.",
    ],
    testSecret: "slack_test_secret",
    docs: "https://api.slack.com/authentication/verifying-requests-from-slack",
  },
  {
    id: "twilio",
    name: "Twilio",
    fn: "verifyTwilio",
    entry: "twilio",
    env: "TWILIO_AUTH_TOKEN",
    headers: ["x-twilio-signature"],
    scheme:
      "HMAC-SHA1 of the full public URL followed by the sorted form fields, base64-encoded. JSON bodies are covered by a `bodySHA256` query parameter in the signed URL.",
    secret:
      "Your account's **Auth Token**: in the Twilio Console, open **Account → API keys & tokens**. Use the primary token unless you are rotating.",
    eventType: "none (Twilio callbacks have no event name)",
    notes: [
      "Twilio signs the **public URL** it called, including the query string. Behind a proxy or tunnel (ngrok, a load balancer), verihook rebuilds it from `x-forwarded-proto` and `x-forwarded-host`. If those aren't forwarded, pass `{ url: 'https://your.public/url' }`.",
      "`result.event` holds the form fields (`Body`, `From`, `To`, ...).",
    ],
    testSecret: "twilio_auth_token",
    docs: "https://www.twilio.com/docs/usage/webhooks/webhooks-security",
  },
  {
    id: "svix",
    name: "Svix",
    fn: "verifySvix",
    entry: "svix",
    env: "SVIX_WEBHOOK_SECRET",
    headers: ["svix-id", "svix-timestamp", "svix-signature", "or webhook-id / webhook-timestamp / webhook-signature"],
    scheme:
      "HMAC-SHA256 of `<id>.<timestamp>.<raw body>`, keyed with the base64 secret, sent as `v1,<base64>`. Standard Webhooks headers (`webhook-*`) are accepted too.",
    secret:
      "The endpoint's **Signing Secret** (`whsec_...`) from the Svix App Portal or dashboard.",
    tolerance: "300 seconds",
    eventType: "the body's `type`",
    notes: [
      "Resend and Clerk send Svix signatures. Use their own identifiers (`'resend'`, `'clerk'`) for clearer logs; the check is the same.",
      "During secret rotation Svix sends several signatures separated by spaces. Any one matching is enough.",
    ],
    testSecret: "whsec_dGVzdF9zZWNyZXRfa2V5X2Zvcl9zdml4XzEyMw==",
    docs: "https://docs.svix.com/receiving/verifying-payloads/how-manual",
  },
  {
    id: "resend",
    name: "Resend",
    fn: "verifyResend",
    entry: "svix",
    env: "RESEND_WEBHOOK_SECRET",
    headers: ["svix-id", "svix-timestamp", "svix-signature"],
    scheme: "Svix signatures: HMAC-SHA256 of `<id>.<timestamp>.<raw body>`.",
    secret:
      "The webhook's **Signing Secret** (`whsec_...`): in the Resend dashboard, open **Webhooks** and select the endpoint.",
    tolerance: "300 seconds",
    eventType: "the body's `type`, e.g. `email.delivered`",
    notes: ["`verifyResend` lives in `verihook/svix` together with Svix and Clerk."],
    testSecret: "whsec_dGVzdF9zZWNyZXRfa2V5X2Zvcl9zdml4XzEyMw==",
    docs: "https://resend.com/docs/dashboard/webhooks/verify-webhooks-requests",
  },
  {
    id: "clerk",
    name: "Clerk",
    fn: "verifyClerk",
    entry: "svix",
    env: "CLERK_WEBHOOK_SIGNING_SECRET",
    headers: ["svix-id", "svix-timestamp", "svix-signature"],
    scheme: "Svix signatures: HMAC-SHA256 of `<id>.<timestamp>.<raw body>`.",
    secret:
      "The endpoint's **Signing Secret** (`whsec_...`): in the Clerk Dashboard, open **Webhooks** and select the endpoint.",
    tolerance: "300 seconds",
    eventType: "the body's `type`, e.g. `user.created`",
    notes: [
      "`verifyClerk` lives in `verihook/svix` together with Svix and Resend.",
      "If you use Clerk middleware, make the webhook route public so it doesn't require a session.",
    ],
    testSecret: "whsec_dGVzdF9zZWNyZXRfa2V5X2Zvcl9zdml4XzEyMw==",
    docs: "https://clerk.com/docs/webhooks/overview",
  },
  {
    id: "meta",
    name: "Meta (WhatsApp, Facebook, Instagram)",
    aliases: ["whatsapp", "facebook", "instagram"],
    fn: "verifyWhatsApp",
    entry: "meta",
    env: "META_APP_SECRET",
    headers: ["x-hub-signature-256"],
    scheme: "HMAC-SHA256 of the raw body, keyed with the app secret, sent as `sha256=<hex>`.",
    secret:
      "Your app's **App Secret**: in the Meta App Dashboard, open **App settings → Basic**. The verify token used in the setup handshake is a different value that you choose.",
    eventType: "the body's `object`, e.g. `whatsapp_business_account`",
    notes: [
      "`'meta'`, `'whatsapp'`, `'facebook'` and `'instagram'` are the same verifier, so `verifyMeta` and `verifyWhatsApp` are interchangeable.",
    ],
    handshake: `Meta checks the URL with a GET request before sending events. Answer it with \`verifyMetaChallenge\`:

\`\`\`ts
import { verifyMetaChallenge } from 'verihook/meta';

// GET /webhooks/whatsapp
export function GET(request: Request) {
  const result = verifyMetaChallenge(new URL(request.url), process.env.META_VERIFY_TOKEN!);
  return result.valid
    ? new Response(result.challenge)
    : new Response('Forbidden', { status: 403 });
}
\`\`\``,
    testSecret: "meta_app_secret",
    docs: "https://developers.facebook.com/docs/graph-api/webhooks/getting-started",
  },
  {
    id: "discord",
    name: "Discord",
    fn: "verifyDiscord",
    entry: "discord",
    env: "DISCORD_PUBLIC_KEY",
    headers: ["x-signature-ed25519", "x-signature-timestamp"],
    scheme: "Ed25519 signature of `<timestamp><raw body>`.",
    secret:
      "The application's **Public Key** (hex): in the Discord Developer Portal, open your application → **General Information**. It's a public key, so there is no shared secret to protect.",
    tolerance: "300 seconds",
    eventType: "the webhook event's `event.type`, or the interaction type (`PING`, ...)",
    notes: [
      "Discord sends invalid signatures on purpose when you save the endpoint URL, and refuses the URL unless you reject them with 401. The adapters already do that.",
    ],
    handshake: `Interactions start with a \`PING\` (type 1) that must be answered with \`{ "type": 1 }\`:

\`\`\`ts
import { createWebhookHandler } from 'verihook/next';

export const POST = createWebhookHandler('discord', process.env.DISCORD_PUBLIC_KEY!, async (payload) => {
  if ((payload as { type?: number }).type === 1) {
    return Response.json({ type: 1 });
  }
  // handle the interaction
});
\`\`\``,
    docs: "https://discord.com/developers/docs/interactions/overview#setting-up-an-endpoint",
  },
  {
    id: "twitter",
    name: "X (Twitter)",
    aliases: ["x"],
    fn: "verifyTwitter",
    entry: "twitter",
    env: "TWITTER_CONSUMER_SECRET",
    headers: ["x-twitter-webhooks-signature"],
    scheme: "HMAC-SHA256 of the raw body, keyed with the consumer secret, sent as `sha256=<base64>`.",
    secret:
      "Your app's **API Key Secret** (consumer secret): in the X Developer Portal, open the app's **Keys and tokens**.",
    eventType: "the payload's `*_events` key, e.g. `tweet_create_events`",
    notes: ["`verifyX` and `verifyXCrc` are aliases of the Twitter functions."],
    handshake: `X sends a CRC check as a GET request with a \`crc_token\`, when you register the webhook and then periodically. Answer it with \`verifyTwitterCrc\`:

\`\`\`ts
import { verifyTwitterCrc } from 'verihook/twitter';

// GET /webhooks/twitter
export async function GET(request: Request) {
  const crcToken = new URL(request.url).searchParams.get('crc_token') ?? '';
  return Response.json(await verifyTwitterCrc(crcToken, process.env.TWITTER_CONSUMER_SECRET!));
}
\`\`\``,
    testSecret: "twitter_consumer_secret",
    docs: "https://docs.x.com/x-api/webhooks/introduction",
  },
  {
    id: "paypal",
    name: "PayPal",
    fn: "verifyPayPal",
    entry: "paypal",
    env: "PAYPAL_WEBHOOK_ID",
    headers: [
      "paypal-transmission-id",
      "paypal-transmission-time",
      "paypal-transmission-sig",
      "paypal-cert-url",
      "paypal-auth-algo",
    ],
    scheme:
      "RSA-SHA256 signature of `<transmission id>|<time>|<webhook id>|<CRC32 of body>`, checked with PayPal's signing certificate.",
    secret:
      "The **Webhook ID** (not a secret): in the PayPal Developer Dashboard, open **Apps & Credentials**, select the app and find the ID in its webhooks list. Pass it as the secret or as `{ webhookId }`. To avoid fetching the certificate, pass the PEM certificate as the secret and the ID as `webhookId`.",
    eventType: "the body's `event_type`, e.g. `PAYMENT.CAPTURE.COMPLETED`",
    notes: [
      "Verification fetches PayPal's certificate from `paypal-cert-url` over HTTPS. Only PayPal API hosts are allowed, and certificates are cached in memory.",
      "Sandbox and live webhooks have different IDs.",
    ],
    signable: false,
    docs: "https://developer.paypal.com/api/rest/webhooks/rest/",
  },
  {
    id: "lemonsqueezy",
    name: "Lemon Squeezy",
    fn: "verifyLemonSqueezy",
    entry: "lemonsqueezy",
    env: "LEMONSQUEEZY_WEBHOOK_SECRET",
    headers: ["x-signature", "x-event-name"],
    scheme: "HMAC-SHA256 of the raw body, hex-encoded.",
    secret:
      "The **signing secret** you entered when creating the webhook under **Settings → Webhooks**.",
    eventType: "`meta.event_name` in the body, e.g. `order_created`",
    notes: [],
    testSecret: "lemon_test_secret",
    docs: "https://docs.lemonsqueezy.com/help/webhooks/signing-requests",
  },
  {
    id: "paddle",
    name: "Paddle",
    fn: "verifyPaddle",
    entry: "paddle",
    env: "PADDLE_WEBHOOK_SECRET",
    headers: ["paddle-signature"],
    scheme: "HMAC-SHA256 of `<ts>:<raw body>`, sent as `ts=<timestamp>;h1=<hex>`.",
    secret:
      "The notification destination's **secret key** (`pdl_ntfset_...`): in Paddle, open **Developer Tools → Notifications**, select the destination and copy its secret key.",
    tolerance: "300 seconds",
    eventType: "the body's `event_type`, e.g. `transaction.completed`",
    notes: ["This covers Paddle Billing. Paddle Classic's `p_signature` scheme isn't supported."],
    testSecret: "pdl_ntfset_test_secret",
    docs: "https://developer.paddle.com/webhooks/signature-verification",
  },
  {
    id: "pagerduty",
    name: "PagerDuty",
    fn: "verifyPagerDuty",
    entry: "pagerduty",
    env: "PAGERDUTY_WEBHOOK_SECRET",
    headers: ["x-pagerduty-signature"],
    scheme: "HMAC-SHA256 of the raw body, sent as `v1=<hex>` (several during rotation).",
    secret:
      "The webhook subscription's **secret**, shown once when you create a V3 webhook subscription under **Integrations → Generic Webhooks (v3)**.",
    eventType: "`event.event_type`, e.g. `incident.triggered`",
    notes: [],
    testSecret: "pagerduty_test_secret",
    docs: "https://developer.pagerduty.com/docs/webhooks-overview#verifying-signatures",
  },
  {
    id: "webflow",
    name: "Webflow",
    fn: "verifyWebflow",
    entry: "webflow",
    env: "WEBFLOW_WEBHOOK_SECRET",
    headers: ["x-webflow-signature", "x-webflow-timestamp"],
    scheme: "HMAC-SHA256 of `<timestamp>:<raw body>`, hex-encoded.",
    secret:
      "For webhooks created through an OAuth app, the app's **client secret**. For webhooks created in **Site settings → Apps & integrations → Webhooks**, the secret shown there.",
    tolerance: "300 seconds",
    eventType: "the body's `triggerType`, e.g. `form_submission`",
    notes: [],
    testSecret: "webflow_test_secret",
    docs: "https://developers.webflow.com/data/docs/working-with-webhooks",
  },
  {
    id: "workos",
    name: "WorkOS",
    fn: "verifyWorkOS",
    entry: "workos",
    env: "WORKOS_WEBHOOK_SECRET",
    headers: ["workos-signature"],
    scheme: "HMAC-SHA256 of `<timestamp>.<raw body>`, sent as `t=<timestamp>, v1=<hex>`.",
    secret:
      "The endpoint's **secret**: in the WorkOS Dashboard, open **Webhooks** and select the endpoint.",
    tolerance: "300 seconds",
    eventType: "the body's `event`, e.g. `dsync.user.created`",
    notes: [],
    testSecret: "workos_test_secret",
    docs: "https://workos.com/docs/events/data-syncing/webhooks",
  },
  {
    id: "linear",
    name: "Linear",
    fn: "verifyLinear",
    entry: "linear",
    env: "LINEAR_WEBHOOK_SECRET",
    headers: ["linear-signature"],
    scheme: "HMAC-SHA256 of the raw body, hex-encoded.",
    secret:
      "The webhook's **signing secret**: in Linear, open **Settings → API → Webhooks** and select the webhook.",
    eventType: "the body's `type`, e.g. `Issue`",
    notes: [
      "Linear also sends `webhookTimestamp` in the body. Check it if you need stricter replay protection.",
    ],
    testSecret: "linear_test_secret",
    docs: "https://linear.app/developers/webhooks",
  },
  {
    id: "razorpay",
    name: "Razorpay",
    fn: "verifyRazorpay",
    entry: "razorpay",
    env: "RAZORPAY_WEBHOOK_SECRET",
    headers: ["x-razorpay-signature"],
    scheme: "HMAC-SHA256 of the raw body, hex-encoded.",
    secret:
      "The **secret** you entered when creating the webhook under **Account & Settings → Webhooks** in the Razorpay Dashboard. It is not your API key secret.",
    eventType: "the body's `event`, e.g. `payment.captured`",
    notes: [],
    testSecret: "razorpay_test_secret",
    docs: "https://razorpay.com/docs/webhooks/validate-test/",
  },
  {
    id: "square",
    name: "Square",
    fn: "verifySquare",
    entry: "square",
    env: "SQUARE_WEBHOOK_SIGNATURE_KEY",
    headers: ["x-square-hmacsha256-signature"],
    scheme: "HMAC-SHA256 of `<notification URL><raw body>`, base64-encoded.",
    secret:
      "The subscription's **Signature Key**: in the Square Developer Console, open your application → **Webhooks → Subscriptions** and select the subscription.",
    eventType: "the body's `type`, e.g. `payment.updated`",
    notes: [
      "Square signs the notification URL exactly as you registered it. Behind a proxy, forward `x-forwarded-proto` and `x-forwarded-host`, or pass `{ url: 'https://your.public/url' }`.",
    ],
    testSecret: "square_signature_key",
    docs: "https://developer.squareup.com/docs/webhooks/step3validate",
  },
  {
    id: "zoom",
    name: "Zoom",
    fn: "verifyZoom",
    entry: "zoom",
    env: "ZOOM_WEBHOOK_SECRET_TOKEN",
    headers: ["x-zm-signature", "x-zm-request-timestamp"],
    scheme: "HMAC-SHA256 of `v0:<timestamp>:<raw body>`, sent as `v0=<hex>`.",
    secret:
      "The app's **Secret Token**: in the Zoom App Marketplace, open your app → **Features → Access**.",
    tolerance: "300 seconds",
    eventType: "the body's `event`, e.g. `meeting.started`",
    notes: [
      "When you save the endpoint, Zoom sends a signed `endpoint.url_validation` event. Respond with `{ plainToken, encryptedToken }`, where `encryptedToken` is the hex HMAC-SHA256 of `payload.plainToken` keyed with the secret token.",
    ],
    testSecret: "zoom_secret_token",
    docs: "https://developers.zoom.us/docs/api/webhooks/",
  },
  {
    id: "cashfree",
    name: "Cashfree",
    region: "India",
    fn: "verifyCashfree",
    entry: "cashfree",
    env: "CASHFREE_CLIENT_SECRET",
    headers: ["x-webhook-signature", "x-webhook-timestamp"],
    scheme: "HMAC-SHA256 of `<timestamp><raw body>` (no separator), base64-encoded.",
    secret:
      "Your Payment Gateway **client secret** (the API secret key) from **Developers → API Keys** in the Cashfree dashboard. Test and production keys differ.",
    tolerance: "300 seconds",
    eventType: "the body's `type`, e.g. `PAYMENT_SUCCESS_WEBHOOK`",
    notes: [],
    testSecret: "cashfree_client_secret",
    docs: "https://www.cashfree.com/docs/payments/online/webhooks/signature-verification",
  },
  {
    id: "phonepe",
    name: "PhonePe",
    region: "India",
    fn: "verifyPhonePe",
    entry: "phonepe",
    env: "PHONEPE_WEBHOOK_CREDENTIALS",
    headers: ["authorization"],
    scheme: "The header is the hex SHA-256 of `<username>:<password>`.",
    secret:
      "The **username and password** you set for the webhook in the PhonePe Business dashboard, passed as `\"username:password\"`.",
    eventType: "the body's `event`, e.g. `checkout.order.completed`",
    notes: [
      "PhonePe doesn't sign the body. The header proves the sender knows your credentials, but confirm the order status with PhonePe's API before fulfilling it.",
    ],
    testSecret: "phonepe_user:phonepe_pass",
    docs: "https://developer.phonepe.com/payment-gateway/website-integration/standard-checkout/api-integration/api-reference/webhook",
  },
  {
    id: "mollie",
    name: "Mollie",
    region: "Europe",
    fn: "verifyMollie",
    entry: "mollie",
    env: "MOLLIE_WEBHOOK_SECRET",
    headers: ["x-mollie-signature"],
    scheme: "HMAC-SHA256 of the raw body, sent as `sha256=<hex>`.",
    secret:
      "The **signing secret** of a next-gen webhook endpoint, from **Developers → Webhooks** in the Mollie dashboard.",
    eventType: "the body's `type`",
    notes: [
      "During a 24-hour secret rotation Mollie sends two signatures; either one matching is enough.",
      "Classic Mollie webhooks (a form post containing only an `id`) are not signed. Fetch the object from the API instead.",
    ],
    testSecret: "mollie_test_secret",
    docs: "https://docs.mollie.com/reference/webhooks-new",
  },
  {
    id: "adyen",
    name: "Adyen",
    region: "Europe",
    fn: "verifyAdyen",
    entry: "adyen",
    env: "ADYEN_HMAC_KEY",
    headers: ["hmacsignature (platform and management webhooks)"],
    scheme:
      "Standard webhooks: base64 HMAC-SHA256 of selected fields of each notification item, in `additionalData.hmacSignature`. Platform and management webhooks: base64 HMAC-SHA256 of the raw body in the `HmacSignature` header.",
    secret:
      "The webhook's **HMAC key** (hex): in the Customer Area, open **Developers → Webhooks**, edit the webhook and generate the HMAC key under its security settings.",
    eventType: "the first item's `eventCode`, e.g. `AUTHORISATION`",
    notes: [
      "Every item in a batch must verify, or the whole request is rejected.",
      "Adyen expects `[accepted]` as the response body for standard webhooks.",
    ],
    testSecret: "0123456789abcdef0123456789abcdef",
    docs: "https://docs.adyen.com/development-resources/webhooks/secure-webhooks/verify-hmac-signatures",
  },
  {
    id: "checkout",
    name: "Checkout.com",
    region: "Europe",
    fn: "verifyCheckout",
    entry: "checkout",
    env: "CHECKOUT_WEBHOOK_SECRET",
    headers: ["cko-signature"],
    scheme: "HMAC-SHA256 of the raw body, hex-encoded.",
    secret:
      "The webhook's **signature key** from the Checkout.com Dashboard, set when you create the webhook or workflow.",
    eventType: "the body's `type`, e.g. `payment_approved`",
    notes: ["The optional `Authorization` header key isn't checked, because the signature already covers the request."],
    testSecret: "checkout_signature_key",
    docs: "https://www.checkout.com/docs/workflows/set-up-your-webhook-receiver",
  },
  {
    id: "authorizenet",
    name: "Authorize.net",
    region: "USA",
    fn: "verifyAuthorizeNet",
    entry: "authorizenet",
    env: "AUTHORIZENET_SIGNATURE_KEY",
    headers: ["x-anet-signature"],
    scheme: "HMAC-SHA512 of the raw body, sent as `sha512=<HEX>`.",
    secret:
      "Your **Signature Key**: in the Merchant Interface, open **Account → Settings → Security Settings → API Credentials & Keys**. Generating a new key disables the old one.",
    eventType: "the body's `eventType`, e.g. `net.authorize.payment.authcapture.created`",
    notes: [],
    testSecret: "authorizenet_signature_key",
    docs: "https://developer.authorize.net/api/reference/features/webhooks.html",
  },
  {
    id: "recurly",
    name: "Recurly",
    region: "USA",
    fn: "verifyRecurly",
    entry: "recurly",
    env: "RECURLY_WEBHOOK_SECRET",
    headers: ["recurly-signature"],
    scheme:
      "HMAC-SHA256 of `<timestamp>.<raw body>`, sent as `<ms timestamp>,<hex>[,<hex>]`.",
    secret: "The webhook endpoint's **secret** from the Recurly integration settings.",
    tolerance: "300 seconds",
    eventType: "`<object_type>.<event_type>`, e.g. `subscription.created`",
    notes: [
      "Only JSON webhooks are signed. XML webhooks can't be verified.",
      "During a 24-hour key rotation the header carries two signatures; either may match.",
    ],
    testSecret: "recurly_test_secret",
    docs: "https://docs.recurly.com/recurly-subscriptions/docs/signature-verification",
  },
  {
    id: "gitlab",
    name: "GitLab",
    fn: "verifyGitLab",
    entry: "gitlab",
    env: "GITLAB_WEBHOOK_SECRET",
    headers: ["webhook-signature, webhook-id, webhook-timestamp (signing token)", "x-gitlab-token (secret token)", "x-gitlab-event"],
    scheme:
      "Signing token (GitLab 19.1+): Standard Webhooks HMAC-SHA256 of `<id>.<timestamp>.<raw body>`. Secret token (older): the token itself in `x-gitlab-token`.",
    secret:
      "The **signing token** (`whsec_...`) or the **secret token** you set on the webhook under **Settings → Webhooks** in the project or group. Pass whichever one you configured.",
    tolerance: "300 seconds (signing token only)",
    eventType: "the body's `object_kind`, or the `x-gitlab-event` header",
    notes: [
      "Prefer the signing token: the secret token is sent in plain text and doesn't protect against replays.",
    ],
    testSecret: "gitlab_secret_token",
    docs: "https://docs.gitlab.com/user/project/integrations/webhooks/",
  },
  {
    id: "bitbucket",
    name: "Bitbucket",
    fn: "verifyBitbucket",
    entry: "bitbucket",
    env: "BITBUCKET_WEBHOOK_SECRET",
    headers: ["x-hub-signature", "x-event-key"],
    scheme: "HMAC-SHA256 of the raw body, sent as `sha256=<hex>`.",
    secret:
      "The **secret** you set on the webhook: in the repository, open **Repository settings → Webhooks** (Bitbucket Cloud or Data Center).",
    eventType: "the `x-event-key` header, e.g. `repo:push`",
    notes: [],
    testSecret: "bitbucket_test_secret",
    docs: "https://support.atlassian.com/bitbucket-cloud/docs/manage-webhooks/",
  },
  {
    id: "vercel",
    name: "Vercel",
    fn: "verifyVercel",
    entry: "vercel",
    env: "VERCEL_WEBHOOK_SECRET",
    headers: ["x-vercel-signature"],
    scheme: "HMAC-SHA1 of the raw body, hex-encoded.",
    secret:
      "For account and team webhooks, the **secret** shown when you create the webhook in **Settings → Webhooks**. For integrations and log drains, the integration's **client secret**.",
    eventType: "the body's `type`, e.g. `deployment.succeeded`",
    notes: [],
    testSecret: "vercel_test_secret",
    docs: "https://vercel.com/docs/webhooks",
  },
  {
    id: "sentry",
    name: "Sentry",
    fn: "verifySentry",
    entry: "sentry",
    env: "SENTRY_CLIENT_SECRET",
    headers: ["sentry-hook-signature", "sentry-hook-resource", "sentry-hook-timestamp"],
    scheme: "HMAC-SHA256 of the raw body, hex-encoded.",
    secret:
      "The integration's **Client Secret**: in Sentry, open **Settings → Developer Settings** and select your internal or public integration.",
    eventType: "`<resource>.<action>`, e.g. `issue.created`",
    notes: [],
    testSecret: "sentry_client_secret",
    docs: "https://docs.sentry.io/organization/integrations/integration-platform/webhooks/",
  },
  {
    id: "twitch",
    name: "Twitch EventSub",
    fn: "verifyTwitch",
    entry: "twitch",
    env: "TWITCH_EVENTSUB_SECRET",
    headers: [
      "twitch-eventsub-message-signature",
      "twitch-eventsub-message-id",
      "twitch-eventsub-message-timestamp",
      "twitch-eventsub-message-type",
    ],
    scheme: "HMAC-SHA256 of `<message id><timestamp><raw body>`, sent as `sha256=<hex>`.",
    secret:
      "The **secret** you passed in `transport.secret` when creating the EventSub subscription (10–100 characters).",
    tolerance: "600 seconds",
    eventType: "the `twitch-eventsub-subscription-type` header, e.g. `channel.follow`",
    notes: [
      "Twitch retries with the same message ID. Use a dedupe store to ignore repeats.",
    ],
    handshake: `After you create a subscription, Twitch sends a \`webhook_callback_verification\` message. Answer it with the challenge as plain text:

\`\`\`ts
import { createWebhookHandler } from 'verihook/next';

export const POST = createWebhookHandler('twitch', process.env.TWITCH_EVENTSUB_SECRET!, async (payload, result) => {
  const body = payload as { challenge?: string };
  if (body.challenge) {
    return new Response(body.challenge, { headers: { 'content-type': 'text/plain' } });
  }
  // handle result.eventType
});
\`\`\``,
    testSecret: "twitch_eventsub_secret",
    docs: "https://dev.twitch.tv/docs/eventsub/handling-webhook-events/",
  },
  {
    id: "telegram",
    name: "Telegram",
    fn: "verifyTelegram",
    entry: "telegram",
    env: "TELEGRAM_WEBHOOK_SECRET_TOKEN",
    headers: ["x-telegram-bot-api-secret-token"],
    scheme: "No signature. Telegram sends the `secret_token` you passed to `setWebhook`.",
    secret:
      "The `secret_token` you chose when calling `setWebhook` (1–256 characters: letters, digits, `_` and `-`). It is not the bot token.",
    eventType: "the update kind, e.g. `message` or `callback_query`",
    notes: [
      "If you called `setWebhook` without `secret_token`, Telegram sends no header and the request can't be verified. Call it again with one.",
    ],
    testSecret: "telegram_secret_token",
    docs: "https://core.telegram.org/bots/api#setwebhook",
  },
  {
    id: "postmark",
    name: "Postmark",
    fn: "verifyPostmark",
    entry: "postmark",
    env: "POSTMARK_WEBHOOK_CREDENTIALS",
    headers: ["authorization (Basic)"],
    scheme: "No signature. HTTP Basic auth from credentials in the webhook URL.",
    secret:
      "The `user:pass` you put in the webhook URL (`https://user:pass@example.com/webhooks/postmark`) in the Postmark server's **Webhooks** settings, passed as `\"user:pass\"`.",
    eventType: "the body's `RecordType`, e.g. `Delivery`",
    notes: ["Postmark doesn't sign webhooks. It also recommends allowlisting its IP addresses."],
    testSecret: "postmark_user:postmark_pass",
    docs: "https://postmarkapp.com/developer/webhooks/webhooks-overview",
  },
  {
    id: "sendgrid",
    name: "SendGrid",
    fn: "verifySendGrid",
    entry: "sendgrid",
    env: "SENDGRID_WEBHOOK_VERIFICATION_KEY",
    headers: ["x-twilio-email-event-webhook-signature", "x-twilio-email-event-webhook-timestamp"],
    scheme: "ECDSA (P-256, SHA-256) signature of `<timestamp><raw body>`.",
    secret:
      "The **verification key** (a public key): in SendGrid, open **Settings → Mail Settings → Event Webhook**, enable **Signed Event Webhook** and copy the key. Base64 or PEM both work.",
    tolerance: "300 seconds",
    eventType: "the first event's `event`, e.g. `delivered`",
    notes: [],
    docs: "https://www.twilio.com/docs/sendgrid/for-developers/tracking-events/getting-started-event-webhook-security-features",
  },
  {
    id: "mailgun",
    name: "Mailgun",
    fn: "verifyMailgun",
    entry: "mailgun",
    env: "MAILGUN_WEBHOOK_SIGNING_KEY",
    headers: ["(signature is in the body)"],
    scheme:
      "HMAC-SHA256 of `<timestamp><token>`, hex-encoded, in the body's `signature` object (JSON) or form fields.",
    secret:
      "The **HTTP webhook signing key**: in the Mailgun dashboard, open **Sending → Webhooks** (or **Settings → API Security**). It is not your API key.",
    tolerance: "300 seconds",
    eventType: "`event-data.event`, e.g. `delivered`",
    notes: [
      "The signature authenticates the sender but doesn't cover the event data. With a dedupe store, the `token` is used as the event ID, as Mailgun recommends.",
    ],
    testSecret: "mailgun_signing_key",
    docs: "https://documentation.mailgun.com/docs/mailgun/user-manual/webhooks/securing-webhooks",
  },
  {
    id: "hubspot",
    name: "HubSpot",
    fn: "verifyHubSpot",
    entry: "hubspot",
    env: "HUBSPOT_CLIENT_SECRET",
    headers: ["x-hubspot-signature-v3", "x-hubspot-request-timestamp", "or x-hubspot-signature (v1/v2)"],
    scheme:
      "v3: base64 HMAC-SHA256 of `<method><url><body><timestamp>`. v1/v2: hex SHA-256 of the client secret with the body (and method and URL).",
    secret:
      "The app's **Client secret**: in your HubSpot developer account, open the app → **Auth**.",
    tolerance: "300 seconds (v3)",
    eventType: "the first event's `subscriptionType`, e.g. `contact.creation`",
    notes: [
      "v2 and v3 sign the public URL. Behind a proxy, forward `x-forwarded-proto` and `x-forwarded-host`, or pass `{ url }`.",
    ],
    testSecret: "hubspot_client_secret",
    docs: "https://developers.hubspot.com/docs/apps/legacy-apps/authentication/validating-requests",
  },
  {
    id: "intercom",
    name: "Intercom",
    fn: "verifyIntercom",
    entry: "intercom",
    env: "INTERCOM_CLIENT_SECRET",
    headers: ["x-hub-signature"],
    scheme: "HMAC-SHA1 of the raw body, sent as `sha1=<hex>`.",
    secret:
      "The app's **client secret**: in the Intercom Developer Hub, open your app → **Basic information**.",
    eventType: "the body's `topic`, e.g. `conversation.user.created`",
    notes: [],
    testSecret: "intercom_client_secret",
    docs: "https://developers.intercom.com/docs/webhooks/setting-up-webhooks",
  },
  {
    id: "calendly",
    name: "Calendly",
    fn: "verifyCalendly",
    entry: "calendly",
    env: "CALENDLY_WEBHOOK_SIGNING_KEY",
    headers: ["calendly-webhook-signature"],
    scheme: "HMAC-SHA256 of `<t>.<raw body>`, sent as `t=<timestamp>,v1=<hex>`.",
    secret:
      "The **signing key** you passed when creating the webhook subscription through the API (`signing_key`).",
    tolerance: "180 seconds",
    eventType: "the body's `event`, e.g. `invitee.created`",
    notes: [
      "Subscriptions created without a `signing_key` aren't signed. Create the subscription with one.",
    ],
    testSecret: "calendly_signing_key",
    docs: "https://developer.calendly.com/api-docs/overview/webhooks/webhook-signatures",
  },
  {
    id: "typeform",
    name: "Typeform",
    fn: "verifyTypeform",
    entry: "typeform",
    env: "TYPEFORM_WEBHOOK_SECRET",
    headers: ["typeform-signature"],
    scheme: "HMAC-SHA256 of the raw body, sent as `sha256=<base64>`.",
    secret:
      "The webhook **secret**: in the form's **Connect → Webhooks**, open the webhook settings and set a secret (or pass `secret` through the API).",
    eventType: "the body's `event_type`, e.g. `form_response`",
    notes: [],
    testSecret: "typeform_test_secret",
    docs: "https://www.typeform.com/developers/webhooks/secure-your-webhooks/",
  },
];
