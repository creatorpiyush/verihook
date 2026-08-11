import { describe, expect, it, vi } from "vitest";
import {
  WebhookErrorCode,
  WebhookVerificationError,
  registerProvider,
  verifyClerk,
  verifyResend,
  verifyWebhook,
  verifyWebhookOrThrow,
  verifyX,
} from "../src/index.js";

describe("Verifier Engine & Errors", () => {
  it("should return invalid result with INVALID_SECRET code when secret is missing", async () => {
    const result = await verifyWebhook(
      "stripe",
      { headers: {}, body: "raw" },
      "",
    );
    expect(result.valid).toBe(false);
    expect(result.code).toBe(WebhookErrorCode.INVALID_SECRET);
    expect(result.reason).toContain("secret is required");
  });

  it("should return UNSUPPORTED_PROVIDER code for unsupported provider name even with empty secret", async () => {
    const resultWithSecret = await verifyWebhook(
      "unknown_provider" as any,
      { headers: {}, body: "raw" },
      "secret",
    );
    expect(resultWithSecret.valid).toBe(false);
    expect(resultWithSecret.code).toBe(WebhookErrorCode.UNSUPPORTED_PROVIDER);
    expect(resultWithSecret.reason).toContain("Unsupported provider");

    const resultWithoutSecret = await verifyWebhook(
      "unknown_provider" as any,
      { headers: {}, body: "raw" },
      "",
    );
    expect(resultWithoutSecret.valid).toBe(false);
    expect(resultWithoutSecret.code).toBe(
      WebhookErrorCode.UNSUPPORTED_PROVIDER,
    );
    expect(resultWithoutSecret.reason).toContain("Unsupported provider");
  });

  it("should throw WebhookVerificationError with accurate code on signature failure", async () => {
    try {
      await verifyWebhookOrThrow(
        "stripe",
        { headers: {}, body: "raw" },
        "secret",
      );
    } catch (err: any) {
      expect(err).toBeInstanceOf(WebhookVerificationError);
      expect(err.code).toBe(WebhookErrorCode.MISSING_HEADER);
      expect(err.provider).toBe("stripe");
    }
  });

  it("should support verifyResend, verifyClerk, and verifyX helpers", async () => {
    const req = { headers: {}, body: "raw" };
    const resendRes = await verifyResend(req, "secret");
    const clerkRes = await verifyClerk(req, "secret");
    const xRes = await verifyX(req, "secret");

    expect(resendRes.code).toBe(WebhookErrorCode.MISSING_HEADER);
    expect(clerkRes.code).toBe(WebhookErrorCode.MISSING_HEADER);
    expect(xRes.code).toBe(WebhookErrorCode.MISSING_HEADER);
  });

  it("should handle telemetry callbacks that throw synchronous exceptions", async () => {
    const throwingPerCallLogger = () => {
      throw new Error("Per-call sync error");
    };
    const res = await verifyWebhook(
      "stripe",
      { headers: {}, body: "raw" },
      "secret",
      {
        onVerify: throwingPerCallLogger,
      },
    );
    expect(res.valid).toBe(false);
  });

  it("should fail fast with INVALID_BODY when plain object passed without rawBody", async () => {
    const result = await verifyWebhook(
      "stripe",
      { headers: {}, body: { event: "test" } },
      "secret",
    );
    expect(result.valid).toBe(false);
    expect(result.code).toBe(WebhookErrorCode.INVALID_BODY);
    expect(result.reason).toContain(
      "Parsed object passed as request body without rawBody",
    );
    expect(result.error).toBeInstanceOf(Error);
  });

  it("should allow registering a custom provider plugin", async () => {
    registerProvider({
      name: "my-plugin",
      async verify(req, secret) {
        return {
          valid: req.headers["x-plugin-sig"] === secret,
          provider: "my-plugin",
        };
      },
    });

    const result = await verifyWebhook(
      "my-plugin" as any,
      { headers: { "x-plugin-sig": "secret123" }, body: "raw" },
      "secret123",
    );
    expect(result.valid).toBe(true);
  });

  it("should allow registering a custom provider plugin with requiresSecret set to false", async () => {
    registerProvider({
      name: "no-secret-plugin",
      requiresSecret: false,
      async verify(req) {
        return {
          valid: req.headers["x-cert-auth"] === "valid",
          provider: "no-secret-plugin",
        };
      },
    });

    const result = await verifyWebhook(
      "no-secret-plugin" as any,
      { headers: { "x-cert-auth": "valid" }, body: "raw" },
      "",
    );
    expect(result.valid).toBe(true);
  });
});
