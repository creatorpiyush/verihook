import {
  computeHmac,
  computeHmacSha1,
  computeHmacSha256,
  computeHmacSha512,
  computeSha256,
  ecdsaRawToDer,
} from "../core/crypto.js";
import { adyenSigningString } from "../providers/adyen.js";
import { hubspotV3Uri } from "../providers/hubspot.js";
import { ProviderName } from "../core/types.js";
import {
  base64ToBytes,
  bytesToBase64,
  bytesToHex,
  hexToBytes,
} from "../utils/encoding.js";

export interface SignWebhookOptions {
  /**
   * Signing secret, exactly as you pass it to `verifyWebhook()`.
   * Required for every provider except `discord` and `sendgrid` (see `privateKey`).
   */
  secret?: string;

  /**
   * Webhook payload. Objects are serialized with `JSON.stringify`; strings are sent as-is.
   * @default {}
   */
  payload?: unknown;

  /**
   * Form fields sent as `application/x-www-form-urlencoded` instead of a JSON payload
   * (Slack slash commands, Twilio SMS/voice callbacks).
   */
  form?: Record<string, string>;

  /**
   * Public URL the webhook is delivered to. Twilio and Square sign it.
   * @default "https://example.com/webhooks/<provider>"
   */
  url?: string;

  /**
   * Signature timestamp in Unix seconds (sent as milliseconds for Cashfree and
   * Recurly). @default now
   */
  timestamp?: number;

  /**
   * Message ID: `svix-id` for Svix-based providers, `webhook-id` for GitLab signing
   * tokens, `twitch-eventsub-message-id` for Twitch. @default random
   */
  webhookId?: string;

  /**
   * Event name sent in a header: `x-github-event` for GitHub (default `"ping"`),
   * `x-shopify-topic` for Shopify (default `"orders/create"`), `x-gitlab-event` for
   * GitLab (`"Push Hook"`), `x-event-key` for Bitbucket (`"repo:push"`),
   * `sentry-hook-resource` for Sentry (`"issue"`) and
   * `twitch-eventsub-subscription-type` for Twitch (`"channel.follow"`).
   */
  event?: string;

  /**
   * Discord: 32-byte Ed25519 private key seed (hex). SendGrid: P-256 private key
   * (base64 PKCS#8). A throwaway key pair is generated when omitted; the matching
   * public key is returned as `secret`.
   */
  privateKey?: string;

  /** Generic provider only: must match the options passed to `verifyWebhook()`. */
  headerName?: string;
  algorithm?: "sha256" | "sha1" | "sha512";
  encoding?: "hex" | "base64" | "prefix-hex";

  /** Extra headers merged into the result (e.g. `x-shopify-topic`). */
  headers?: Record<string, string>;
}

export interface SignedWebhook {
  provider: ProviderName;
  method: "POST";
  /** URL the request should be sent to (includes `bodySHA256` for Twilio JSON webhooks). */
  url: string;
  headers: Record<string, string>;
  /** Exact raw body that was signed. Send it unmodified. */
  body: string;
  /** Value to pass to `verifyWebhook()` as the secret (the public key for Discord). */
  secret: string;
}

/** Built-in providers `signWebhook()` can sign (everything except PayPal). */
export const SIGNABLE_PROVIDERS: ReadonlySet<string> = new Set([
  "stripe",
  "github",
  "shopify",
  "slack",
  "twilio",
  "svix",
  "resend",
  "clerk",
  "meta",
  "whatsapp",
  "facebook",
  "instagram",
  "discord",
  "twitter",
  "x",
  "lemonsqueezy",
  "paddle",
  "pagerduty",
  "webflow",
  "workos",
  "linear",
  "razorpay",
  "square",
  "zoom",
  "cashfree",
  "phonepe",
  "mollie",
  "adyen",
  "checkout",
  "authorizenet",
  "recurly",
  "gitlab",
  "bitbucket",
  "vercel",
  "sentry",
  "twitch",
  "telegram",
  "postmark",
  "sendgrid",
  "mailgun",
  "hubspot",
  "intercom",
  "calendly",
  "typeform",
  "generic",
]);

// SPKI DER prefix for an uncompressed P-256 public key (0x04 || x || y follows).
const P256_SPKI_HEADER = hexToBytes(
  "3059301306072a8648ce3d020106082a8648ce3d030107034200",
);

function base64UrlToBytes(value: string): Uint8Array {
  const b64 = value.replace(/-/g, "+").replace(/_/g, "/");
  return base64ToBytes(b64.padEnd(Math.ceil(b64.length / 4) * 4, "="));
}

async function signEcdsaP256(
  pkcs8Base64: string | undefined,
  data: string,
): Promise<{ publicKey: string; signature: string }> {
  const subtle = globalThis.crypto.subtle;
  const algorithm = { name: "ECDSA", namedCurve: "P-256" };
  let privateKey: CryptoKey;
  if (pkcs8Base64) {
    try {
      privateKey = await subtle.importKey(
        "pkcs8",
        base64ToBytes(pkcs8Base64) as unknown as BufferSource,
        algorithm,
        true,
        ["sign"],
      );
    } catch {
      throw new Error(
        "[verihook/testing] SendGrid privateKey must be a base64 PKCS#8 P-256 key",
      );
    }
  } else {
    const pair = (await subtle.generateKey(algorithm, true, [
      "sign",
      "verify",
    ])) as CryptoKeyPair;
    privateKey = pair.privateKey;
  }

  const jwk = await subtle.exportKey("jwk", privateKey);
  const x = base64UrlToBytes(jwk.x as string);
  const y = base64UrlToBytes(jwk.y as string);
  const spki = new Uint8Array(
    P256_SPKI_HEADER.length + 1 + x.length + y.length,
  );
  spki.set(P256_SPKI_HEADER, 0);
  spki[P256_SPKI_HEADER.length] = 0x04;
  spki.set(x, P256_SPKI_HEADER.length + 1);
  spki.set(y, P256_SPKI_HEADER.length + 1 + x.length);

  const raw = await subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    new TextEncoder().encode(data) as unknown as BufferSource,
  );
  return {
    publicKey: bytesToBase64(spki),
    signature: bytesToBase64(ecdsaRawToDer(new Uint8Array(raw))),
  };
}

// PKCS#8 DER prefix for a raw 32-byte Ed25519 private key seed.
const ED25519_PKCS8_HEADER = hexToBytes("302e020100300506032b657004220420");

function randomId(prefix: string): string {
  const bytes = new Uint8Array(12);
  globalThis.crypto.getRandomValues(bytes);
  return `${prefix}${bytesToHex(bytes)}`;
}

function requireSecret(provider: string, secret: string | undefined): string {
  if (!secret) {
    throw new Error(
      `[verihook/testing] signWebhook("${provider}") requires options.secret`,
    );
  }
  return secret;
}

async function signEd25519(
  seedHex: string | undefined,
  data: string,
): Promise<{ publicKeyHex: string; signatureHex: string }> {
  const subtle = globalThis.crypto.subtle;
  let privateKey: CryptoKey;
  if (seedHex) {
    const seed = hexToBytes(seedHex);
    if (seed.length !== 32) {
      throw new Error(
        "[verihook/testing] Discord privateKey must be a 32-byte hex seed",
      );
    }
    const pkcs8 = new Uint8Array(ED25519_PKCS8_HEADER.length + seed.length);
    pkcs8.set(ED25519_PKCS8_HEADER, 0);
    pkcs8.set(seed, ED25519_PKCS8_HEADER.length);
    privateKey = await subtle.importKey(
      "pkcs8",
      pkcs8 as unknown as BufferSource,
      { name: "Ed25519" },
      true,
      ["sign"],
    );
  } else {
    const pair = (await subtle.generateKey({ name: "Ed25519" }, true, [
      "sign",
      "verify",
    ])) as CryptoKeyPair;
    privateKey = pair.privateKey;
  }

  // The JWK form of a private key carries the public key in `x` (base64url).
  const jwk = await subtle.exportKey("jwk", privateKey);
  const x = (jwk.x as string).replace(/-/g, "+").replace(/_/g, "/");
  const publicKeyHex = bytesToHex(
    base64ToBytes(x.padEnd(Math.ceil(x.length / 4) * 4, "=")),
  );
  const signature = await subtle.sign(
    { name: "Ed25519" },
    privateKey,
    new TextEncoder().encode(data) as unknown as BufferSource,
  );
  return { publicKeyHex, signatureHex: bytesToHex(new Uint8Array(signature)) };
}

/**
 * Builds a correctly signed webhook request for tests and local tooling.
 *
 * The result is plain data, so it works with `fetch`, supertest, `app.inject()`,
 * or a direct call to `verifyWebhook()`:
 *
 * ```ts
 * const hook = await signWebhook("stripe", { secret, payload: { id: "evt_1" } });
 * await request(app).post("/webhooks/stripe").set(hook.headers).send(hook.body);
 * ```
 *
 * PayPal is not supported: PayPal signs with its own private RSA key.
 */
export async function signWebhook(
  provider: ProviderName,
  options: SignWebhookOptions = {},
): Promise<SignedWebhook> {
  const name = String(provider).toLowerCase();
  let url = options.url || `https://example.com/webhooks/${name}`;
  const timestamp = options.timestamp ?? Math.floor(Date.now() / 1000);
  const headers: Record<string, string> = {};

  let body: string;
  if (options.form) {
    body = new URLSearchParams(options.form).toString();
    headers["content-type"] = "application/x-www-form-urlencoded";
  } else {
    const payload = options.payload ?? {};
    body = typeof payload === "string" ? payload : JSON.stringify(payload);
    headers["content-type"] = "application/json";
  }

  let secret = options.secret ?? "";

  switch (name) {
    case "stripe": {
      secret = requireSecret(name, secret);
      const hmac = await computeHmacSha256(secret, `${timestamp}.${body}`);
      headers["stripe-signature"] = `t=${timestamp},v1=${bytesToHex(hmac)}`;
      break;
    }

    case "github": {
      secret = requireSecret(name, secret);
      const hmac = await computeHmacSha256(secret, body);
      headers["x-hub-signature-256"] = `sha256=${bytesToHex(hmac)}`;
      headers["x-github-event"] = options.event || "ping";
      headers["x-github-delivery"] = randomId("");
      break;
    }

    case "meta":
    case "whatsapp":
    case "facebook":
    case "instagram": {
      secret = requireSecret(name, secret);
      const hmac = await computeHmacSha256(secret, body);
      headers["x-hub-signature-256"] = `sha256=${bytesToHex(hmac)}`;
      break;
    }

    case "shopify": {
      secret = requireSecret(name, secret);
      const hmac = await computeHmacSha256(secret, body);
      headers["x-shopify-hmac-sha256"] = bytesToBase64(hmac);
      headers["x-shopify-topic"] = options.event || "orders/create";
      headers["x-shopify-webhook-id"] = randomId("");
      break;
    }

    case "twitter":
    case "x": {
      secret = requireSecret(name, secret);
      const hmac = await computeHmacSha256(secret, body);
      headers["x-twitter-webhooks-signature"] = `sha256=${bytesToBase64(hmac)}`;
      break;
    }

    case "lemonsqueezy": {
      secret = requireSecret(name, secret);
      headers["x-signature"] = bytesToHex(
        await computeHmacSha256(secret, body),
      );
      break;
    }

    case "linear": {
      secret = requireSecret(name, secret);
      headers["linear-signature"] = bytesToHex(
        await computeHmacSha256(secret, body),
      );
      break;
    }

    case "razorpay": {
      secret = requireSecret(name, secret);
      headers["x-razorpay-signature"] = bytesToHex(
        await computeHmacSha256(secret, body),
      );
      break;
    }

    case "pagerduty": {
      secret = requireSecret(name, secret);
      const hmac = await computeHmacSha256(secret, body);
      headers["x-pagerduty-signature"] = `v1=${bytesToHex(hmac)}`;
      break;
    }

    case "paddle": {
      secret = requireSecret(name, secret);
      const hmac = await computeHmacSha256(secret, `${timestamp}:${body}`);
      headers["paddle-signature"] = `ts=${timestamp};h1=${bytesToHex(hmac)}`;
      break;
    }

    case "webflow": {
      secret = requireSecret(name, secret);
      const hmac = await computeHmacSha256(secret, `${timestamp}:${body}`);
      headers["x-webflow-timestamp"] = String(timestamp);
      headers["x-webflow-signature"] = `sha256=${bytesToHex(hmac)}`;
      break;
    }

    case "workos": {
      secret = requireSecret(name, secret);
      const hmac = await computeHmacSha256(secret, `${timestamp}.${body}`);
      headers["workos-signature"] = `t=${timestamp},v1=${bytesToHex(hmac)}`;
      break;
    }

    case "slack":
    case "zoom": {
      secret = requireSecret(name, secret);
      const hmac = await computeHmacSha256(secret, `v0:${timestamp}:${body}`);
      const prefix = name === "slack" ? "x-slack" : "x-zm";
      headers[`${prefix}-request-timestamp`] = String(timestamp);
      headers[`${prefix}-signature`] = `v0=${bytesToHex(hmac)}`;
      break;
    }

    case "svix":
    case "resend":
    case "clerk":
    case "gitlab": {
      secret = requireSecret(name, secret);
      if (name === "gitlab") {
        headers["x-gitlab-event"] = options.event || "Push Hook";
        // A plain secret token is sent as-is; a `whsec_` signing token signs the request.
        if (!secret.startsWith("whsec_")) {
          headers["x-gitlab-token"] = secret;
          break;
        }
      }
      const prefix = name === "gitlab" ? "webhook" : "svix";
      const keyBytes = base64ToBytes(
        secret.startsWith("whsec_") ? secret.slice(6) : secret,
      );
      const msgId = options.webhookId || randomId("msg_");
      const hmac = await computeHmacSha256(
        keyBytes,
        `${msgId}.${timestamp}.${body}`,
      );
      headers[`${prefix}-id`] = msgId;
      headers[`${prefix}-timestamp`] = String(timestamp);
      headers[`${prefix}-signature`] = `v1,${bytesToBase64(hmac)}`;
      break;
    }

    case "twilio": {
      secret = requireSecret(name, secret);
      let dataToSign: string;
      if (options.form) {
        dataToSign = url;
        const params = new URLSearchParams(body);
        for (const key of Array.from(new Set(params.keys())).sort()) {
          for (const value of params.getAll(key)) {
            dataToSign += key + value;
          }
        }
      } else {
        const hash = bytesToHex(await computeSha256(body));
        url = `${url}${url.includes("?") ? "&" : "?"}bodySHA256=${hash}`;
        dataToSign = url;
      }
      headers["x-twilio-signature"] = bytesToBase64(
        await computeHmacSha1(secret, dataToSign),
      );
      break;
    }

    case "square": {
      secret = requireSecret(name, secret);
      headers["x-square-hmacsha256-signature"] = bytesToBase64(
        await computeHmacSha256(secret, url + body),
      );
      break;
    }

    case "cashfree": {
      secret = requireSecret(name, secret);
      const timestampMs = String(timestamp * 1000);
      headers["x-webhook-timestamp"] = timestampMs;
      headers["x-webhook-signature"] = bytesToBase64(
        await computeHmacSha256(secret, `${timestampMs}${body}`),
      );
      break;
    }

    case "phonepe": {
      secret = requireSecret(name, secret);
      if (!secret.includes(":")) {
        throw new Error(
          '[verihook/testing] PhonePe secret must be "username:password"',
        );
      }
      headers["authorization"] = bytesToHex(await computeSha256(secret));
      break;
    }

    case "mollie": {
      secret = requireSecret(name, secret);
      const hmac = await computeHmacSha256(secret, body);
      headers["x-mollie-signature"] = `sha256=${bytesToHex(hmac)}`;
      break;
    }

    case "checkout": {
      secret = requireSecret(name, secret);
      headers["cko-signature"] = bytesToHex(
        await computeHmacSha256(secret, body),
      );
      break;
    }

    case "authorizenet": {
      secret = requireSecret(name, secret);
      const hmac = await computeHmacSha512(secret, body);
      headers["x-anet-signature"] = `sha512=${bytesToHex(hmac).toUpperCase()}`;
      break;
    }

    case "recurly": {
      secret = requireSecret(name, secret);
      const timestampMs = timestamp * 1000;
      const hmac = await computeHmacSha256(secret, `${timestampMs}.${body}`);
      headers["recurly-signature"] = `${timestampMs},${bytesToHex(hmac)}`;
      break;
    }

    case "adyen": {
      secret = requireSecret(name, secret);
      let key: Uint8Array;
      try {
        key = hexToBytes(secret.trim());
      } catch {
        throw new Error(
          "[verihook/testing] Adyen secret must be the hex HMAC key from the Customer Area",
        );
      }
      const payload = options.payload as
        { notificationItems?: unknown } | undefined;
      if (
        !options.form &&
        payload &&
        typeof payload === "object" &&
        Array.isArray(payload.notificationItems)
      ) {
        // Standard notifications carry an HMAC per item in additionalData.
        const items = await Promise.all(
          payload.notificationItems.map(async (entry) => {
            const item = (entry as { NotificationRequestItem?: object })
              .NotificationRequestItem as Record<string, unknown>;
            const additionalData = (item.additionalData ?? {}) as object;
            const hmacSignature = bytesToBase64(
              await computeHmacSha256(key, adyenSigningString(item)),
            );
            return {
              ...(entry as object),
              NotificationRequestItem: {
                ...item,
                additionalData: { ...additionalData, hmacSignature },
              },
            };
          }),
        );
        body = JSON.stringify({ ...payload, notificationItems: items });
      } else {
        headers["hmacsignature"] = bytesToBase64(
          await computeHmacSha256(key, body),
        );
        headers["protocol"] = "HmacSHA256";
      }
      break;
    }

    case "bitbucket":
    case "intercom": {
      secret = requireSecret(name, secret);
      if (name === "bitbucket") {
        const hmac = await computeHmacSha256(secret, body);
        headers["x-hub-signature"] = `sha256=${bytesToHex(hmac)}`;
        headers["x-event-key"] = options.event || "repo:push";
        headers["x-request-uuid"] = randomId("");
      } else {
        const hmac = await computeHmacSha1(secret, body);
        headers["x-hub-signature"] = `sha1=${bytesToHex(hmac)}`;
      }
      break;
    }

    case "vercel": {
      secret = requireSecret(name, secret);
      headers["x-vercel-signature"] = bytesToHex(
        await computeHmacSha1(secret, body),
      );
      break;
    }

    case "sentry": {
      secret = requireSecret(name, secret);
      headers["sentry-hook-signature"] = bytesToHex(
        await computeHmacSha256(secret, body),
      );
      headers["sentry-hook-resource"] = options.event || "issue";
      headers["sentry-hook-timestamp"] = String(timestamp);
      headers["request-id"] = randomId("");
      break;
    }

    case "twitch": {
      secret = requireSecret(name, secret);
      const messageId = options.webhookId || randomId("");
      const isoTimestamp = new Date(timestamp * 1000).toISOString();
      const hmac = await computeHmacSha256(
        secret,
        `${messageId}${isoTimestamp}${body}`,
      );
      headers["twitch-eventsub-message-id"] = messageId;
      headers["twitch-eventsub-message-timestamp"] = isoTimestamp;
      headers["twitch-eventsub-message-signature"] =
        `sha256=${bytesToHex(hmac)}`;
      headers["twitch-eventsub-message-type"] = "notification";
      headers["twitch-eventsub-subscription-type"] =
        options.event || "channel.follow";
      headers["twitch-eventsub-subscription-version"] = "1";
      break;
    }

    case "telegram": {
      secret = requireSecret(name, secret);
      headers["x-telegram-bot-api-secret-token"] = secret;
      break;
    }

    case "postmark": {
      secret = requireSecret(name, secret);
      if (!secret.includes(":")) {
        throw new Error(
          '[verihook/testing] Postmark secret must be "username:password"',
        );
      }
      headers["authorization"] =
        `Basic ${bytesToBase64(new TextEncoder().encode(secret))}`;
      break;
    }

    case "sendgrid": {
      const signed = await signEcdsaP256(
        options.privateKey,
        `${timestamp}${body}`,
      );
      secret = signed.publicKey;
      headers["x-twilio-email-event-webhook-signature"] = signed.signature;
      headers["x-twilio-email-event-webhook-timestamp"] = String(timestamp);
      break;
    }

    case "mailgun": {
      secret = requireSecret(name, secret);
      const token = randomId("") + randomId("");
      const signature = bytesToHex(
        await computeHmacSha256(secret, `${timestamp}${token}`),
      );
      // Mailgun signs in the body: top-level fields for form posts, a
      // `signature` object for JSON webhooks.
      if (options.form) {
        body = new URLSearchParams({
          ...options.form,
          timestamp: String(timestamp),
          token,
          signature,
        }).toString();
      } else {
        const payload = options.payload ?? {};
        if (typeof payload !== "object" || Array.isArray(payload)) {
          throw new Error(
            "[verihook/testing] Mailgun payload must be an object (the signature is added to it)",
          );
        }
        body = JSON.stringify({
          ...payload,
          signature: { timestamp: String(timestamp), token, signature },
        });
      }
      break;
    }

    case "hubspot": {
      secret = requireSecret(name, secret);
      const timestampMs = String(timestamp * 1000);
      const hmac = await computeHmacSha256(
        secret,
        `POST${hubspotV3Uri(url)}${body}${timestampMs}`,
      );
      headers["x-hubspot-signature-v3"] = bytesToBase64(hmac);
      headers["x-hubspot-request-timestamp"] = timestampMs;
      break;
    }

    case "calendly": {
      secret = requireSecret(name, secret);
      const hmac = await computeHmacSha256(secret, `${timestamp}.${body}`);
      headers["calendly-webhook-signature"] =
        `t=${timestamp},v1=${bytesToHex(hmac)}`;
      break;
    }

    case "typeform": {
      secret = requireSecret(name, secret);
      const hmac = await computeHmacSha256(secret, body);
      headers["typeform-signature"] = `sha256=${bytesToBase64(hmac)}`;
      break;
    }

    case "discord": {
      const signed = await signEd25519(
        options.privateKey,
        `${timestamp}${body}`,
      );
      secret = signed.publicKeyHex;
      headers["x-signature-timestamp"] = String(timestamp);
      headers["x-signature-ed25519"] = signed.signatureHex;
      break;
    }

    case "paypal":
      throw new Error(
        "[verihook/testing] PayPal webhooks are signed with PayPal's private RSA key and cannot be signed locally. Use the PayPal Developer Dashboard webhook simulator.",
      );

    case "generic": {
      secret = requireSecret(name, secret);
      const algorithm = options.algorithm ?? "sha256";
      const encoding = options.encoding ?? "hex";
      const alg =
        algorithm === "sha1"
          ? "SHA-1"
          : algorithm === "sha512"
            ? "SHA-512"
            : "SHA-256";
      const hmac = await computeHmac(alg, secret, body);
      headers[(options.headerName || "x-signature").toLowerCase()] =
        encoding === "base64"
          ? bytesToBase64(hmac)
          : encoding === "prefix-hex"
            ? `${algorithm}=${bytesToHex(hmac)}`
            : bytesToHex(hmac);
      break;
    }

    default:
      throw new Error(
        `[verihook/testing] signWebhook does not know how to sign "${provider}". Custom providers must build their own signed requests.`,
      );
  }

  return {
    provider,
    method: "POST",
    url,
    headers: { ...headers, ...options.headers },
    body,
    secret,
  };
}

/**
 * Same as `signWebhook()`, returned as a Fetch API `Request` for handlers that take
 * one directly (Next.js route handlers, Hono, Cloudflare Workers).
 */
export async function createSignedRequest(
  provider: ProviderName,
  options: SignWebhookOptions = {},
): Promise<Request> {
  const signed = await signWebhook(provider, options);
  return new Request(signed.url, {
    method: signed.method,
    headers: signed.headers,
    body: signed.body,
  });
}
