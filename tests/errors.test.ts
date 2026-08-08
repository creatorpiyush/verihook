import { describe, expect, it } from "vitest";
import {
  InvalidBodyError,
  UnsupportedProviderError,
  WebhookVerificationError,
} from "../src/core/errors.js";
import { WebhookErrorCode } from "../src/core/types.js";

describe("Domain Errors", () => {
  it("should instantiate WebhookVerificationError with default and custom code", () => {
    const errDefault = new WebhookVerificationError("stripe", "bad sig");
    expect(errDefault.name).toBe("WebhookVerificationError");
    expect(errDefault.provider).toBe("stripe");
    expect(errDefault.reason).toBe("bad sig");
    expect(errDefault.code).toBe(WebhookErrorCode.INVALID_SIGNATURE);

    const errCustom = new WebhookVerificationError(
      "stripe",
      "expired",
      WebhookErrorCode.EXPIRED_TIMESTAMP,
    );
    expect(errCustom.code).toBe(WebhookErrorCode.EXPIRED_TIMESTAMP);
  });

  it("should instantiate InvalidBodyError with custom and default message", () => {
    const errDefault = new InvalidBodyError();
    expect(errDefault.name).toBe("InvalidBodyError");
    expect(errDefault.code).toBe(WebhookErrorCode.INVALID_BODY);
    expect(errDefault.message).toContain(
      "Parsed object passed as request body",
    );

    const errCustom = new InvalidBodyError("custom invalid body");
    expect(errCustom.message).toBe("custom invalid body");
  });

  it("should instantiate UnsupportedProviderError", () => {
    const err = new UnsupportedProviderError("unknown_provider", [
      "stripe",
      "github",
    ]);
    expect(err.name).toBe("UnsupportedProviderError");
    expect(err.provider).toBe("unknown_provider");
    expect(err.code).toBe(WebhookErrorCode.UNSUPPORTED_PROVIDER);
    expect(err.message).toContain('Unsupported provider "unknown_provider"');
  });
});
