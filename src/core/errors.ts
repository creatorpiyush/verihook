import { ProviderName, VerificationErrorCode, WebhookErrorCode } from './types.js';

export class WebhookVerificationError extends Error {
  public readonly provider: ProviderName;
  public readonly reason: string;
  public readonly code: VerificationErrorCode;

  constructor(
    provider: ProviderName,
    reason: string,
    code: VerificationErrorCode = WebhookErrorCode.INVALID_SIGNATURE
  ) {
    super(`[verihook] ${provider} verification failed: ${reason}`);
    this.name = 'WebhookVerificationError';
    this.provider = provider;
    this.reason = reason;
    this.code = code;

    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, WebhookVerificationError);
    }
  }
}

export class InvalidBodyError extends Error {
  public readonly code: VerificationErrorCode = WebhookErrorCode.INVALID_BODY;

  constructor(message?: string) {
    super(
      message ||
        'Parsed object passed as request body without rawBody. Webhook signature verification requires the exact, unparsed raw payload string/Buffer before JSON parsing. Pass rawBody or configure middleware (e.g. express.raw({ type: "*/*" })) to preserve original request bytes.'
    );
    this.name = 'InvalidBodyError';

    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, InvalidBodyError);
    }
  }
}

export class UnsupportedProviderError extends Error {
  public readonly code: VerificationErrorCode = WebhookErrorCode.UNSUPPORTED_PROVIDER;
  public readonly provider: string;

  constructor(provider: string, supportedProviders: string[]) {
    super(`[verihook] Unsupported provider "${provider}". Supported providers: ${supportedProviders.join(', ')}`);
    this.name = 'UnsupportedProviderError';
    this.provider = provider;

    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, UnsupportedProviderError);
    }
  }
}
