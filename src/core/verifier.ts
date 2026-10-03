import { getProviderVerifier } from "../providers/index.js";
import { normalizeRequest } from "../utils/normalize-request.js";
import { extractEventId } from "./dedupe.js";
import { diagnoseFailure, warnHintOnce } from "./diagnostics.js";
import { WebhookVerificationError } from "./errors.js";
import { parseEvent, resolveEventType } from "./event.js";
import type { EventFor, ResolveEvent } from "./event-types.js";
import { getGlobalLogger } from "./logger.js";
import {
  ProviderName,
  VerificationErrorCode,
  VerificationResult,
  VerifyWebhookOptions,
  WebhookErrorCode,
  WebhookRequestInput,
  WebhookVerificationEvent,
} from "./types.js";

const KNOWN_ERROR_CODES = new Set<string>(Object.values(WebhookErrorCode));

function dispatchTelemetry(
  result: VerificationResult,
  startTime: number,
  attemptedAt: number,
  options?: VerifyWebhookOptions,
): void {
  const durationMs = Math.round((performance.now() - startTime) * 100) / 100;
  const event: WebhookVerificationEvent = {
    provider: result.provider,
    valid: result.valid,
    code: result.code,
    reason: result.reason,
    hint: result.hint,
    eventType: result.eventType,
    timestamp: result.timestamp,
    durationMs,
    attemptedAt,
    error: result.error,
  };

  const perCallLogger = options?.onVerify || options?.log;
  const globalLogger = getGlobalLogger();

  const isDev =
    typeof process !== "undefined" && process.env?.NODE_ENV !== "production";

  if (perCallLogger) {
    try {
      Promise.resolve(perCallLogger(event)).catch((err) => {
        if (isDev) {
          console.warn("[verihook] per-call telemetry logger failed:", err);
        }
      });
    } catch (err) {
      if (isDev) {
        console.warn("[verihook] per-call telemetry logger exception:", err);
      }
    }
  }

  if (globalLogger) {
    try {
      Promise.resolve(globalLogger(event)).catch((err) => {
        if (isDev) {
          console.warn("[verihook] global telemetry logger failed:", err);
        }
      });
    } catch (err) {
      if (isDev) {
        console.warn("[verihook] global telemetry logger exception:", err);
      }
    }
  }
}

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
  const attemptedAt = Date.now();
  const startTime = performance.now();

  let result: VerificationResult;
  try {
    const verifier = getProviderVerifier(provider);

    if (!secret && verifier.requiresSecret !== false) {
      result = {
        valid: false,
        provider,
        code: WebhookErrorCode.INVALID_SECRET,
        reason: "Webhook secret is required",
      };
    } else {
      const normalizedReq = await normalizeRequest(req);
      result = await verifier.verify(normalizedReq, secret || "", options);

      if (!result.valid && !result.hint) {
        const hint = diagnoseFailure(
          provider,
          normalizedReq,
          secret || "",
          result,
          options,
        );
        if (hint) {
          result = { ...result, hint };
          warnHintOnce(provider, hint);
        }
      }

      if (result.valid) {
        const event = parseEvent(normalizedReq);
        const eventType = resolveEventType(verifier, event, normalizedReq);
        result = { ...result, event, eventType };
      }

      if (result.valid && options?.dedupeStore) {
        const eventId =
          options.eventId || (await extractEventId(provider, normalizedReq));
        const dedupeKey = `${provider}:${eventId}`;
        const ttlMs = options.dedupeTtlMs ?? 300_000;
        const isDuplicate = await options.dedupeStore.hasOrSet(
          dedupeKey,
          ttlMs,
        );
        if (isDuplicate) {
          result = {
            valid: false,
            provider,
            code: WebhookErrorCode.DUPLICATE_EVENT,
            reason: "Duplicate webhook event detected (replay protection)",
            timestamp: result.timestamp,
          };
        } else {
          result = { ...result, dedupeKey };
        }
      }
    }
  } catch (err: unknown) {
    const errObj = err as Record<string, unknown> | null;
    // Only surface our own codes; e.g. Node's "ERR_*" codes map to UNKNOWN_ERROR.
    const code: VerificationErrorCode =
      errObj && KNOWN_ERROR_CODES.has(errObj.code as string)
        ? (errObj.code as VerificationErrorCode)
        : WebhookErrorCode.UNKNOWN_ERROR;
    const message = err instanceof Error ? err.message : String(err);

    result = {
      valid: false,
      provider,
      code,
      reason: message || "Unknown verification error",
      error: err instanceof Error ? err : new Error(String(err)),
    };
  }

  dispatchTelemetry(result, startTime, attemptedAt, options);
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
