import { getProviderVerifier } from "../providers/index.js";
import { WebhookVerificationError } from "./errors.js";
import type { EventFor, ResolveEvent } from "./event-types.js";
import { runVerification } from "./run.js";
import {
  ProviderName,
  ProviderVerifyFunction,
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
function shortcut<P extends ProviderName>(
  provider: P,
): ProviderVerifyFunction<P> {
  return <TEvent = EventFor<P>>(
    req: WebhookRequestInput,
    secret: string,
    opts?: VerifyWebhookOptions,
  ) =>
    verifyWebhook(provider, req, secret, opts) as Promise<
      VerificationResult<TEvent>
    >;
}

export const verifyStripe: ProviderVerifyFunction<"stripe"> =
  shortcut("stripe");
export const verifyGitHub: ProviderVerifyFunction<"github"> =
  shortcut("github");
export const verifyShopify: ProviderVerifyFunction<"shopify"> =
  shortcut("shopify");
export const verifySlack: ProviderVerifyFunction<"slack"> = shortcut("slack");
export const verifyTwilio: ProviderVerifyFunction<"twilio"> =
  shortcut("twilio");
export const verifySvix: ProviderVerifyFunction<"svix"> = shortcut("svix");
export const verifyResend: ProviderVerifyFunction<"resend"> =
  shortcut("resend");
export const verifyClerk: ProviderVerifyFunction<"clerk"> = shortcut("clerk");
export const verifyLinear: ProviderVerifyFunction<"linear"> =
  shortcut("linear");
export const verifyRazorpay: ProviderVerifyFunction<"razorpay"> =
  shortcut("razorpay");
export const verifySquare: ProviderVerifyFunction<"square"> =
  shortcut("square");
export const verifyZoom: ProviderVerifyFunction<"zoom"> = shortcut("zoom");
export const verifyMeta: ProviderVerifyFunction<"meta"> = shortcut("meta");
export const verifyWhatsApp: ProviderVerifyFunction<"whatsapp"> =
  shortcut("whatsapp");
export const verifyDiscord: ProviderVerifyFunction<"discord"> =
  shortcut("discord");
export const verifyTwitter: ProviderVerifyFunction<"twitter"> =
  shortcut("twitter");
export const verifyX: ProviderVerifyFunction<"twitter"> = verifyTwitter;
export const verifyPayPal: ProviderVerifyFunction<"paypal"> =
  shortcut("paypal");
export const verifyLemonSqueezy: ProviderVerifyFunction<"lemonsqueezy"> =
  shortcut("lemonsqueezy");
export const verifyPaddle: ProviderVerifyFunction<"paddle"> =
  shortcut("paddle");
export const verifyPagerDuty: ProviderVerifyFunction<"pagerduty"> =
  shortcut("pagerduty");
export const verifyWebflow: ProviderVerifyFunction<"webflow"> =
  shortcut("webflow");
export const verifyWorkOS: ProviderVerifyFunction<"workos"> =
  shortcut("workos");
export const verifyCashfree: ProviderVerifyFunction<"cashfree"> =
  shortcut("cashfree");
export const verifyPhonePe: ProviderVerifyFunction<"phonepe"> =
  shortcut("phonepe");
export const verifyMollie: ProviderVerifyFunction<"mollie"> =
  shortcut("mollie");
export const verifyAdyen: ProviderVerifyFunction<"adyen"> = shortcut("adyen");
export const verifyCheckout: ProviderVerifyFunction<"checkout"> =
  shortcut("checkout");
export const verifyAuthorizeNet: ProviderVerifyFunction<"authorizenet"> =
  shortcut("authorizenet");
export const verifyRecurly: ProviderVerifyFunction<"recurly"> =
  shortcut("recurly");
export const verifyGitLab: ProviderVerifyFunction<"gitlab"> =
  shortcut("gitlab");
export const verifyBitbucket: ProviderVerifyFunction<"bitbucket"> =
  shortcut("bitbucket");
export const verifyVercel: ProviderVerifyFunction<"vercel"> =
  shortcut("vercel");
export const verifySentry: ProviderVerifyFunction<"sentry"> =
  shortcut("sentry");
export const verifyTwitch: ProviderVerifyFunction<"twitch"> =
  shortcut("twitch");
export const verifyTelegram: ProviderVerifyFunction<"telegram"> =
  shortcut("telegram");
export const verifyPostmark: ProviderVerifyFunction<"postmark"> =
  shortcut("postmark");
export const verifySendGrid: ProviderVerifyFunction<"sendgrid"> =
  shortcut("sendgrid");
export const verifyMailgun: ProviderVerifyFunction<"mailgun"> =
  shortcut("mailgun");
export const verifyHubSpot: ProviderVerifyFunction<"hubspot"> =
  shortcut("hubspot");
export const verifyIntercom: ProviderVerifyFunction<"intercom"> =
  shortcut("intercom");
export const verifyCalendly: ProviderVerifyFunction<"calendly"> =
  shortcut("calendly");
export const verifyTypeform: ProviderVerifyFunction<"typeform"> =
  shortcut("typeform");
