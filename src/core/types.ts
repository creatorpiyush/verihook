export type ProviderName =
  | "stripe"
  | "github"
  | "shopify"
  | "slack"
  | "twilio"
  | "svix"
  | "resend"
  | "clerk"
  | "linear"
  | "razorpay"
  | "square"
  | "zoom"
  | "meta"
  | "whatsapp"
  | "facebook"
  | "instagram"
  | "discord"
  | "twitter"
  | "x"
  | "paypal"
  | "lemonsqueezy"
  | "paddle"
  | "pagerduty"
  | "webflow"
  | "workos"
  | "generic"
  | (string & {});

export type WebhookHeaders =
  Headers | Record<string, string | string[] | undefined> | Map<string, string>;

export interface WebhookRequestInputObject {
  headers?: WebhookHeaders;
  body?: string | Uint8Array | ArrayBuffer | Record<string, unknown> | unknown;
  rawBody?: string | Uint8Array | ArrayBuffer;
  url?: string;
  originalUrl?: string;
  method?: string;
  /** Request protocol as exposed by Express/Fastify (`req.protocol`), e.g. "http". */
  protocol?: string;
}

export type WebhookRequestInput = Request | WebhookRequestInputObject;

export interface NormalizedWebhookRequest {
  headers: Record<string, string>;
  rawBody: string;
  url?: string;
  method?: string;
  protocol?: string;
}

export interface DedupeStore {
  /**
   * Checks if an event ID is already present in the store.
   * If not present, records the ID with the given TTL in milliseconds.
   * @returns `true` if the event is a duplicate (already seen), `false` if it is new.
   */
  hasOrSet(key: string, ttlMs: number): Promise<boolean> | boolean;

  /**
   * Removes a recorded event ID (optional). When implemented, the framework
   * middlewares call it if the webhook handler fails, so the provider's retry
   * is processed instead of being rejected as a duplicate.
   */
  delete?(key: string): Promise<void> | void;

  /**
   * Clears all stored event IDs (optional, useful for testing or flushing).
   */
  clear?(): Promise<void> | void;
}

export interface MemoryDedupeStoreOptions {
  /**
   * Default time-to-live in milliseconds for stored event IDs.
   * @default 300000 (5 minutes)
   */
  ttlMs?: number;

  /**
   * Maximum number of keys allowed in the store before LRU eviction.
   * @default 10000
   */
  maxSize?: number;
}

export interface VerifyWebhookOptions {
  /**
   * Maximum allowed age of the webhook signature in seconds.
   * Prevents replay attacks for providers that include timestamps.
   * Set to 0 to disable timestamp verification.
   * @default 300 (5 minutes)
   */
  tolerance?: number;

  /**
   * Explicit URL override. Required for Twilio signature verification if not available on the request object.
   */
  url?: string;

  /**
   * PayPal Webhook ID configured in PayPal Developer Dashboard (required for PayPal signature verification).
   */
  webhookId?: string;

  /**
   * Current timestamp in seconds or milliseconds for testing or custom time synchronization.
   */
  now?: number;

  /**
   * Custom signature header name (used for generic or custom providers).
   */
  headerName?: string;

  /**
   * Custom HMAC algorithm (e.g. 'sha256', 'sha1', 'sha512'). Used for generic provider.
   * @default 'sha256'
   */
  algorithm?: "sha256" | "sha1" | "sha512";

  /**
   * Encoding of the signature in header (e.g. 'hex', 'base64', 'prefix-hex').
   */
  encoding?: "hex" | "base64" | "prefix-hex";

  /**
   * Telemetry callback invoked on every verification attempt (pass/fail).
   */
  onVerify?: WebhookLoggerFn;

  /**
   * Telemetry callback invoked on every verification attempt (alias for onVerify).
   */
  log?: WebhookLoggerFn;

  /**
   * Maximum allowed body size in bytes when the Express or Next.js middleware reads the request body (defaults to 2MB = 2,097,152 bytes).
   */
  maxBodySize?: number;

  /**
   * Optional deduplication store instance (e.g. MemoryDedupeStore or custom Redis store).
   * Automatically rejects duplicate events within the TTL window.
   */
  dedupeStore?: DedupeStore;

  /**
   * Time-to-live in milliseconds for deduplication records when `dedupeStore` is specified.
   * @default 300000 (5 minutes)
   */
  dedupeTtlMs?: number;

  /**
   * Explicit event ID override for deduplication tracking.
   * If omitted, `verihook` automatically extracts provider event ID or computes a hash fallback.
   */
  eventId?: string;
}

export interface WebhookVerificationEvent {
  /**
   * Target provider identifier (e.g. 'stripe', 'github', 'twilio').
   */
  provider: ProviderName;

  /**
   * Whether signature verification succeeded.
   */
  valid: boolean;

  /**
   * Error code if verification failed.
   */
  code?: VerificationErrorCode;

  /**
   * Human-readable failure explanation if applicable.
   */
  reason?: string;

  /**
   * Extracted webhook timestamp if available (Unix epoch in seconds).
   */
  timestamp?: number;

  /**
   * Verification execution duration in milliseconds.
   */
  durationMs: number;

  /**
   * Epoch timestamp (ms) when verification was attempted.
   */
  attemptedAt: number;

  /**
   * Preserved raw Error instance if an unexpected exception was caught.
   */
  error?: Error;
}

export type WebhookLoggerFn = (
  event: WebhookVerificationEvent,
) => void | Promise<void>;

export enum WebhookErrorCode {
  INVALID_SIGNATURE = "INVALID_SIGNATURE",
  EXPIRED_TIMESTAMP = "EXPIRED_TIMESTAMP",
  MISSING_HEADER = "MISSING_HEADER",
  MISSING_URL = "MISSING_URL",
  INVALID_SECRET = "INVALID_SECRET",
  INVALID_BODY = "INVALID_BODY",
  UNSUPPORTED_PROVIDER = "UNSUPPORTED_PROVIDER",
  DUPLICATE_EVENT = "DUPLICATE_EVENT",
  UNKNOWN_ERROR = "UNKNOWN_ERROR",
}

export type VerificationErrorCode = `${WebhookErrorCode}`;

export interface VerificationResult {
  /**
   * Indicates whether the signature verification succeeded.
   */
  valid: boolean;

  /**
   * The provider name used for verification.
   */
  provider: ProviderName;

  /**
   * Structured error code for observability and incident debugging.
   */
  code?: VerificationErrorCode;

  /**
   * If verification failed, provides a clear human-readable explanation.
   */
  reason?: string;

  /**
   * Extracted webhook timestamp if applicable (Unix epoch in seconds).
   */
  timestamp?: number;

  /**
   * Preserved raw Error instance if an unexpected exception was caught during verification.
   */
  error?: Error;

  /**
   * Key recorded in `options.dedupeStore` for this event, when deduplication ran.
   * Pass it to `dedupeStore.delete()` to allow a retry if processing fails.
   */
  dedupeKey?: string;
}

export interface ProviderVerifier {
  name: ProviderName;

  /**
   * Whether this provider requires a `secret` argument to verify.
   * Set to `false` for providers that authenticate via certificate/public-key
   * verification instead of a shared HMAC secret (e.g. PayPal's RSA cert chain).
   * @default true
   */
  requiresSecret?: boolean;

  /**
   * Verifies the request signature against the given secret.
   */
  verify(
    req: NormalizedWebhookRequest,
    secret: string,
    options?: VerifyWebhookOptions,
  ): Promise<VerificationResult>;
}
