import { resolveSignedUrl } from "../utils/request-url.js";
import {
  NormalizedWebhookRequest,
  ProviderName,
  VerificationResult,
  VerifyWebhookOptions,
  WebhookErrorCode,
} from "./types.js";

// Signature header that identifies each provider's webhooks.
const SIGNATURE_HEADERS: Array<[header: string, provider: string]> = [
  ["stripe-signature", "stripe"],
  ["x-shopify-hmac-sha256", "shopify"],
  ["x-slack-signature", "slack"],
  ["x-twilio-signature", "twilio"],
  ["svix-signature", "svix"],
  ["x-signature-ed25519", "discord"],
  ["x-twitter-webhooks-signature", "twitter"],
  ["paypal-transmission-sig", "paypal"],
  ["paddle-signature", "paddle"],
  ["x-pagerduty-signature", "pagerduty"],
  ["x-webflow-signature", "webflow"],
  ["workos-signature", "workos"],
  ["linear-signature", "linear"],
  ["x-razorpay-signature", "razorpay"],
  ["x-square-hmacsha256-signature", "square"],
  ["x-zm-signature", "zoom"],
  ["x-github-event", "github"],
  ["x-hub-signature-256", "github or meta"],
];

const SVIX_FAMILY = new Set(["svix", "resend", "clerk"]);
const URL_SIGNING = new Set(["twilio", "square"]);
const RAW_BODY_FIX =
  'Pass the exact raw bytes: e.g. express.raw({ type: "*/*" }), `await request.text()`, or the verihook/express and verihook/next adapters.';

function byteLength(value: string): number {
  return new TextEncoder().encode(value).length;
}

function bodyHint(req: NormalizedWebhookRequest): string | undefined {
  const declared = Number(req.headers["content-length"]);
  // Compressed or chunked bodies don't have a comparable length.
  if (!Number.isFinite(declared) || req.headers["content-encoding"]) {
    return undefined;
  }
  if (declared > 0 && !req.rawBody) {
    return `The body is empty but content-length is ${declared}: the request stream was probably read by another middleware first. ${RAW_BODY_FIX}`;
  }
  const actual = byteLength(req.rawBody);
  if (actual !== declared) {
    return `The body is ${actual} bytes but content-length is ${declared}: it was modified before verification, usually parsed as JSON and re-serialized. ${RAW_BODY_FIX}`;
  }
  return undefined;
}

function secretHint(provider: string, secret: string): string | undefined {
  if (secret !== secret.trim()) {
    return "The secret has leading or trailing whitespace. Check how it is loaded from your environment.";
  }
  if (/^(["']).*\1$/.test(secret)) {
    return "The secret is wrapped in quotes. Remove the quotes from the value in your environment.";
  }
  if (provider === "stripe") {
    if (/^(sk|rk|pk)_/.test(secret)) {
      return "This looks like a Stripe API key. Use the endpoint's webhook signing secret (whsec_...) from the Stripe dashboard or `stripe listen`.";
    }
    if (!secret.startsWith("whsec_")) {
      return "Stripe webhook signing secrets start with whsec_. Check you are using the signing secret of this endpoint (test and live mode secrets differ).";
    }
  }
  if (SVIX_FAMILY.has(provider) && !secret.startsWith("whsec_")) {
    return "Svix-based signing secrets (Svix, Resend, Clerk) start with whsec_. Copy the endpoint's signing secret from the dashboard.";
  }
  return undefined;
}

function otherProviderHint(
  provider: string,
  req: NormalizedWebhookRequest,
): string | undefined {
  if (Object.keys(req.headers).length === 0) {
    return "No request headers were passed. Pass the incoming request's headers (req.headers or request.headers).";
  }
  for (const [header, owner] of SIGNATURE_HEADERS) {
    if (req.headers[header] && !owner.split(" or ").includes(provider)) {
      return `The request has a "${header}" header, which ${owner} sends. Is this endpoint verifying the right provider?`;
    }
  }
  return undefined;
}

/**
 * Suggests a likely cause for a failed verification. Hints are for the developer
 * (logs, telemetry) and should not be sent back in HTTP responses.
 */
export function diagnoseFailure(
  provider: ProviderName,
  req: NormalizedWebhookRequest,
  secret: string,
  result: VerificationResult,
  options?: VerifyWebhookOptions,
): string | undefined {
  const name = String(provider).toLowerCase();

  switch (result.code) {
    case WebhookErrorCode.INVALID_SIGNATURE: {
      const hint = bodyHint(req) || secretHint(name, secret);
      if (hint) return hint;
      if (URL_SIGNING.has(name)) {
        const url = resolveSignedUrl(req, options?.url);
        return `${name} signs the public URL of your endpoint; it was checked against ${url}. Behind a proxy or tunnel, forward x-forwarded-proto and x-forwarded-host, or pass options.url.`;
      }
      return undefined;
    }
    case WebhookErrorCode.MISSING_HEADER:
      return otherProviderHint(name, req);
    case WebhookErrorCode.EXPIRED_TIMESTAMP:
      return "If you are replaying a saved request (tests or fixtures), pass options.now or increase options.tolerance. Otherwise check the server clock.";
    default:
      return undefined;
  }
}

const warnedHints = new Set<string>();

/** Prints each distinct hint once outside production and test runs. */
export function warnHintOnce(provider: ProviderName, hint: string): void {
  const env = typeof process !== "undefined" ? process.env?.NODE_ENV : "";
  if (env === "production" || env === "test" || warnedHints.has(hint)) {
    return;
  }
  warnedHints.add(hint);
  console.warn(`[verihook] ${provider} verification hint: ${hint}`);
}
