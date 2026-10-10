/**
 * `verihook/send`: sign and send webhooks to your customers, as a producer.
 *
 * Webhooks are signed with Standard Webhooks (https://www.standardwebhooks.com):
 *   webhook-id, webhook-timestamp,
 *   webhook-signature: v1,<base64 HMAC-SHA256 of `<id>.<timestamp>.<body>`>
 * Receivers verify them with `verifyWebhook("standard-webhooks", ...)`, Svix's
 * libraries or any Standard Webhooks implementation.
 */
import { computeHmacSha256 } from "./core/crypto.js";
import type { WebhookSecret } from "./core/types.js";
import { svixSecretKey } from "./providers/svix.js";
import { readWebBodyWithLimit } from "./utils/body.js";
import { bytesToBase64, bytesToHex } from "./utils/encoding.js";
import { isNonPublicHost } from "./utils/ssrf.js";

export interface OutgoingWebhook {
  /**
   * Signing secret(s) of the receiving endpoint (`whsec_...`, see
   * `generateWebhookSecret`). Pass several during a rotation: the request then
   * carries one signature per secret, and the receiver accepts any of them.
   */
  secret: WebhookSecret;
  /** Body: objects are sent as JSON, strings as-is. */
  payload: unknown;
  /**
   * Unique message ID (`webhook-id`). Reuse it when retrying the same event, so
   * receivers can deduplicate. @default random `msg_...`
   */
  id?: string;
  /** Signature time in Unix seconds. @default now */
  timestamp?: number;
}

export interface SignedOutgoingWebhook {
  id: string;
  timestamp: number;
  /** The exact signed body. Send it unmodified. */
  body: string;
  /** `webhook-id`, `webhook-timestamp`, `webhook-signature` and `content-type`. */
  headers: Record<string, string>;
}

export interface SendWebhookOptions extends OutgoingWebhook {
  /** Extra headers. The `webhook-*` signature headers can't be overridden. */
  headers?: Record<string, string>;
  /** Abort the request after this many milliseconds. @default 10000 */
  timeoutMs?: number;
  /**
   * Allow loopback, private-network and cloud-metadata hosts. Only for local
   * development: with customer-supplied URLs this enables SSRF. @default false
   */
  allowPrivateNetworks?: boolean;
  /**
   * `fetch` to send with, e.g. one bound to an SSRF-safe agent or egress proxy.
   * @default globalThis.fetch
   */
  fetch?: typeof fetch;
}

export interface SendWebhookResult {
  /** `true` for a 2xx response. */
  ok: boolean;
  /** HTTP status, when a response was received. */
  status?: number;
  /** Response body (first 64 KiB are read; larger bodies are left out). */
  responseBody?: string;
  /** Why the delivery failed: blocked URL, network error or timeout. */
  error?: Error;
  id: string;
  timestamp: number;
  durationMs: number;
}

const MAX_RESPONSE_BYTES = 64 * 1024;

function randomBytes(length: number): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(length));
}

/** A new random signing secret for an endpoint: `whsec_` + 32 bytes, base64. */
export function generateWebhookSecret(): string {
  return `whsec_${bytesToBase64(randomBytes(32))}`;
}

/** Signs a webhook without sending it. Pure: no I/O. */
export async function signOutgoingWebhook(
  webhook: OutgoingWebhook,
): Promise<SignedOutgoingWebhook> {
  const secrets = (
    typeof webhook.secret === "string" ? [webhook.secret] : webhook.secret
  ).filter((s) => typeof s === "string" && s !== "");
  if (secrets.length === 0) {
    throw new TypeError("[verihook/send] a signing secret is required");
  }

  const id = webhook.id ?? `msg_${bytesToHex(randomBytes(16))}`;
  const timestamp = webhook.timestamp ?? Math.floor(Date.now() / 1000);
  const body =
    typeof webhook.payload === "string"
      ? webhook.payload
      : JSON.stringify(webhook.payload ?? {});

  const signatures = await Promise.all(
    secrets.map(async (secret) => {
      const hmac = await computeHmacSha256(
        svixSecretKey(secret),
        `${id}.${timestamp}.${body}`,
      );
      return `v1,${bytesToBase64(hmac)}`;
    }),
  );

  return {
    id,
    timestamp,
    body,
    headers: {
      "content-type": "application/json",
      "webhook-id": id,
      "webhook-timestamp": String(timestamp),
      "webhook-signature": signatures.join(" "),
    },
  };
}

/** Why `url` must not be sent to, or `undefined` when it may. */
function blockedReason(
  url: string,
  allowPrivateNetworks: boolean,
): string | undefined {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return `Invalid webhook URL: ${url}`;
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    return `Webhook URL must use http(s), got "${parsed.protocol}"`;
  }
  if (!allowPrivateNetworks && isNonPublicHost(parsed.hostname)) {
    return `Webhook URL host "${parsed.hostname}" is not a public address (pass allowPrivateNetworks for local development)`;
  }
  return undefined;
}

/**
 * Signs and POSTs one webhook. Makes a single attempt and never throws for
 * delivery failures (blocked URL, network error, timeout, non-2xx): check
 * `result.ok` and retry from your own queue, reusing `result.id`. Redirects are
 * not followed, so a receiver can't bounce the request to another host.
 *
 * Hosts that are literal private, loopback or metadata addresses are refused.
 * A public hostname that *resolves* to a private address is not caught: send
 * through an egress proxy, or pass a `fetch` that blocks those, when the URLs
 * come from your customers.
 */
export async function sendWebhook(
  url: string,
  options: SendWebhookOptions,
): Promise<SendWebhookResult> {
  const started = Date.now();
  const signed = await signOutgoingWebhook(options);
  const result = (fields: Partial<SendWebhookResult>): SendWebhookResult => ({
    ok: false,
    ...fields,
    id: signed.id,
    timestamp: signed.timestamp,
    durationMs: Date.now() - started,
  });

  const blocked = blockedReason(url, options.allowPrivateNetworks ?? false);
  if (blocked) {
    return result({ error: new Error(blocked) });
  }

  // Signature headers go last so extra headers can't replace them.
  const headers = new Headers(options.headers);
  for (const [name, value] of Object.entries(signed.headers)) {
    if (name === "content-type" && headers.has(name)) continue;
    headers.set(name, value);
  }

  const send = options.fetch ?? globalThis.fetch;
  let response: Response;
  try {
    response = await send(url, {
      method: "POST",
      headers,
      body: signed.body,
      redirect: "manual",
      signal: AbortSignal.timeout(options.timeoutMs ?? 10_000),
    });
  } catch (err) {
    return result({
      error: err instanceof Error ? err : new Error(String(err)),
    });
  }

  let responseBody: string | undefined;
  try {
    responseBody = await readWebBodyWithLimit(
      response as unknown as Request,
      MAX_RESPONSE_BYTES,
    );
  } catch {
    // Too large or unreadable: the status is what matters.
  }

  // Node returns the 3xx itself; browsers and workers an opaque status-0 one.
  const redirected =
    response.type === "opaqueredirect" ||
    (response.status >= 300 && response.status < 400);
  return result({
    ok: response.status >= 200 && response.status < 300,
    status: response.status,
    responseBody,
    ...(redirected
      ? { error: new Error(`Redirect (${response.status}) not followed`) }
      : {}),
  });
}
