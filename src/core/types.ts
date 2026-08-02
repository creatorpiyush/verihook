export type ProviderName =
  | 'stripe'
  | 'github'
  | 'shopify'
  | 'slack'
  | 'twilio'
  | 'svix'
  | 'resend'
  | 'clerk'
  | 'linear'
  | 'razorpay'
  | 'square'
  | 'zoom'
  | 'meta'
  | 'whatsapp'
  | 'facebook'
  | 'instagram'
  | 'discord'
  | 'twitter'
  | 'x'
  | 'paypal'
  | 'lemonsqueezy'
  | 'paddle'
  | 'pagerduty'
  | 'webflow'
  | 'workos'
  | 'generic'
  | (string & {});

export type WebhookHeaders =
  | Headers
  | Record<string, string | string[] | undefined>
  | Map<string, string>;

export interface WebhookRequestInputObject {
  headers?: WebhookHeaders;
  body?: string | Uint8Array | ArrayBuffer | Record<string, any> | any;
  rawBody?: string | Uint8Array | ArrayBuffer;
  url?: string;
  originalUrl?: string;
  method?: string;
}

export type WebhookRequestInput = Request | WebhookRequestInputObject;

export interface NormalizedWebhookRequest {
  headers: Record<string, string>;
  rawBody: string;
  url?: string;
  method?: string;
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
  algorithm?: 'sha256' | 'sha1' | 'sha512';

  /**
   * Encoding of the signature in header (e.g. 'hex', 'base64', 'prefix-hex').
   */
  encoding?: 'hex' | 'base64' | 'prefix-hex';

  /**
   * Telemetry callback invoked on every verification attempt (pass/fail).
   */
  onVerify?: WebhookLoggerFn;

  /**
   * Telemetry callback invoked on every verification attempt (alias for onVerify).
   */
  log?: WebhookLoggerFn;
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

export type WebhookLoggerFn = (event: WebhookVerificationEvent) => void | Promise<void>;

export enum WebhookErrorCode {
  INVALID_SIGNATURE = 'INVALID_SIGNATURE',
  EXPIRED_TIMESTAMP = 'EXPIRED_TIMESTAMP',
  MISSING_HEADER = 'MISSING_HEADER',
  MISSING_URL = 'MISSING_URL',
  INVALID_SECRET = 'INVALID_SECRET',
  INVALID_BODY = 'INVALID_BODY',
  UNSUPPORTED_PROVIDER = 'UNSUPPORTED_PROVIDER',
  UNKNOWN_ERROR = 'UNKNOWN_ERROR',
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
}

export interface ProviderVerifier {
  name: ProviderName;

  /**
   * Verifies the request signature against the given secret.
   */
  verify(
    req: NormalizedWebhookRequest,
    secret: string,
    options?: VerifyWebhookOptions
  ): Promise<VerificationResult>;
}
