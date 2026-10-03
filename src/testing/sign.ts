import {
  computeHmac,
  computeHmacSha1,
  computeHmacSha256,
  computeHmacSha512,
  computeSha256,
} from "../core/crypto.js";
import { adyenSigningString } from "../providers/adyen.js";
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
   * Required for every provider except `discord` (see `privateKey`).
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

  /** Message ID for Svix-based providers (`svix-id`). @default random */
  webhookId?: string;

  /**
   * Event name sent in a header: `x-github-event` for GitHub (default `"ping"`),
   * `x-shopify-topic` for Shopify (default `"orders/create"`).
   */
  event?: string;

  /**
   * Discord only: 32-byte Ed25519 private key seed (hex). A throwaway key pair is
   * generated when omitted; the matching public key is returned as `secret`.
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
  "generic",
]);

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
      headers["paddle-signature"] = `ts=${timestamp};h=${bytesToHex(hmac)}`;
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
    case "clerk": {
      secret = requireSecret(name, secret);
      const keyBytes = base64ToBytes(
        secret.startsWith("whsec_") ? secret.slice(6) : secret,
      );
      const msgId = options.webhookId || randomId("msg_");
      const hmac = await computeHmacSha256(
        keyBytes,
        `${msgId}.${timestamp}.${body}`,
      );
      headers["svix-id"] = msgId;
      headers["svix-timestamp"] = String(timestamp);
      headers["svix-signature"] = `v1,${bytesToBase64(hmac)}`;
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
