import { getProviderVerifier } from "../providers/index.js";
import { WebhookVerificationError } from "./errors.js";
import type { EventFor, ResolveEvent } from "./event-types.js";
import { runVerification } from "./run.js";
import {
  ProviderName,
  VerificationErrorCode,
  VerificationResult,
  VerifyWebhookOptions,
  WebhookErrorCode,
  WebhookRequestInput,
} from "./types.js";

/**
 * Universal webhook verification function.
 * Normalizes input request formats (Fetch Request, Express req, Next.js, Fastify, custom)
 * and verifies signature against provider specification.
 *
 * On success, `result.event` holds the parsed payload, typed for built-in providers.
 * Pass a type argument to use your own: `verifyWebhook<Stripe.Event>("stripe", ...)`.
 *
 * @returns VerificationResult containing valid status, error code, reason, timestamp, parsed event, and optional raw error.
 */
export async function verifyWebhook<
  TEvent = never,
  P extends ProviderName = ProviderName,
>(
  provider: P,
  req: WebhookRequestInput,
  secret: string,
  options?: VerifyWebhookOptions,
): Promise<VerificationResult<ResolveEvent<TEvent, P>>> {
  const result = await runVerification(
    provider,
    () => getProviderVerifier(provider),
    req,
    secret,
    options,
  );
  return result as VerificationResult<ResolveEvent<TEvent, P>>;
}

/**
 * Universal webhook verification function that throws `WebhookVerificationError`
 * if verification fails.
 *
 * @throws WebhookVerificationError when verification fails.
 */
export async function verifyWebhookOrThrow<
  TEvent = never,
  P extends ProviderName = ProviderName,
>(
  provider: P,
  req: WebhookRequestInput,
  secret: string,
  options?: VerifyWebhookOptions,
): Promise<VerificationResult<ResolveEvent<TEvent, P>>> {
  const result = await verifyWebhook<TEvent, P>(provider, req, secret, options);
  if (!result.valid) {
    throw new WebhookVerificationError(
      result.provider,
      result.reason || "Verification failed",
      (result.code as VerificationErrorCode) ||
        WebhookErrorCode.INVALID_SIGNATURE,
      result.hint,
    );
  }
  return result;
}

// Provider-specific helper shortcuts
function shortcut<P extends ProviderName>(provider: P) {
  return <TEvent = EventFor<P>>(
    req: WebhookRequestInput,
    secret: string,
    opts?: VerifyWebhookOptions,
  ) =>
    verifyWebhook(provider, req, secret, opts) as Promise<
      VerificationResult<TEvent>
    >;
}

export const verifyStripe = shortcut("stripe");
export const verifyGitHub = shortcut("github");
export const verifyShopify = shortcut("shopify");
export const verifySlack = shortcut("slack");
export const verifyTwilio = shortcut("twilio");
export const verifySvix = shortcut("svix");
export const verifyResend = shortcut("resend");
export const verifyClerk = shortcut("clerk");
export const verifyLinear = shortcut("linear");
export const verifyRazorpay = shortcut("razorpay");
export const verifySquare = shortcut("square");
export const verifyZoom = shortcut("zoom");
export const verifyMeta = shortcut("meta");
export const verifyWhatsApp = shortcut("whatsapp");
export const verifyDiscord = shortcut("discord");
export const verifyTwitter = shortcut("twitter");
export const verifyX = verifyTwitter;
export const verifyPayPal = shortcut("paypal");
export const verifyLemonSqueezy = shortcut("lemonsqueezy");
export const verifyPaddle = shortcut("paddle");
export const verifyPagerDuty = shortcut("pagerduty");
export const verifyWebflow = shortcut("webflow");
export const verifyWorkOS = shortcut("workos");
export const verifyCashfree = shortcut("cashfree");
export const verifyPhonePe = shortcut("phonepe");
export const verifyMollie = shortcut("mollie");
export const verifyAdyen = shortcut("adyen");
export const verifyCheckout = shortcut("checkout");
export const verifyAuthorizeNet = shortcut("authorizenet");
export const verifyRecurly = shortcut("recurly");
export const verifyGitLab = shortcut("gitlab");
export const verifyBitbucket = shortcut("bitbucket");
export const verifyVercel = shortcut("vercel");
export const verifySentry = shortcut("sentry");
export const verifyTwitch = shortcut("twitch");
export const verifyTelegram = shortcut("telegram");
export const verifyPostmark = shortcut("postmark");
export const verifySendGrid = shortcut("sendgrid");
export const verifyMailgun = shortcut("mailgun");
export const verifyHubSpot = shortcut("hubspot");
export const verifyIntercom = shortcut("intercom");
export const verifyCalendly = shortcut("calendly");
export const verifyTypeform = shortcut("typeform");
