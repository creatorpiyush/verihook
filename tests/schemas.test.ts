import { describe, expect, it } from "vitest";
import {
  validateCliArgs,
  validateVerifyWebhookOptions,
} from "../src/schemas/index.js";

describe("Schema Boundary Validation", () => {
  it("should validate valid CLI arguments", () => {
    const res = validateCliArgs({
      provider: "stripe",
      url: "http://localhost:3000/webhooks/stripe",
      secret: "whsec_test",
      event: "payment_intent.succeeded",
      printCurl: true,
      allowRemote: true,
    });
    expect(res.success).toBe(true);
    expect(res.data.provider).toBe("stripe");
    expect(res.data.url).toBe("http://localhost:3000/webhooks/stripe");
    expect(res.data.event).toBe("payment_intent.succeeded");
    expect(res.data.printCurl).toBe(true);
    expect(res.data.allowRemote).toBe(true);
  });

  it("should reject invalid CLI types", () => {
    const res = validateCliArgs({
      provider: "",
      url: 123 as any,
      secret: 456 as any,
      event: 789 as any,
    });
    expect(res.success).toBe(false);
    expect(res.errors).toContain("provider must be a non-empty string");
    expect(res.errors).toContain("url must be a string");
    expect(res.errors).toContain("secret must be a string");
    expect(res.errors).toContain("event must be a string");
  });

  it("should validate VerifyWebhookOptions", () => {
    const res = validateVerifyWebhookOptions({
      tolerance: 300,
      algorithm: "sha256",
      encoding: "hex",
      maxBodySize: 1048576,
    });
    expect(res.success).toBe(true);
    expect(res.data.tolerance).toBe(300);
    expect(res.data.maxBodySize).toBe(1048576);
  });

  it("should reject invalid VerifyWebhookOptions", () => {
    const res = validateVerifyWebhookOptions({
      tolerance: -5,
      algorithm: "md5" as any,
      encoding: "raw" as any,
      maxBodySize: -100,
    });
    expect(res.success).toBe(false);
    expect(res.errors).toContain("tolerance must be a non-negative number");
    expect(res.errors).toContain(
      'algorithm must be one of "sha256", "sha1", or "sha512"',
    );
    expect(res.errors).toContain(
      'encoding must be one of "hex", "base64", or "prefix-hex"',
    );
    expect(res.errors).toContain("maxBodySize must be a positive number");
  });

  it("should validate command, forwardTo, port, and path options", () => {
    const validRes = validateCliArgs({
      command: "listen",
      forwardTo: "http://localhost:3000/webhooks/stripe",
      port: "8080",
      path: "/webhooks/stripe",
    });
    expect(validRes.success).toBe(true);
    expect(validRes.data.command).toBe("listen");
    expect(validRes.data.forwardTo).toBe(
      "http://localhost:3000/webhooks/stripe",
    );
    expect(validRes.data.port).toBe(8080);
    expect(validRes.data.path).toBe("/webhooks/stripe");

    const invalidRes = validateCliArgs({
      command: "unknown" as any,
      forwardTo: 123 as any,
      port: 70000,
      path: 456 as any,
    });
    expect(invalidRes.success).toBe(false);
    expect(invalidRes.errors).toContain(
      'command must be either "simulate" or "listen"',
    );
    expect(invalidRes.errors).toContain("forwardTo must be a string");
    expect(invalidRes.errors).toContain(
      "port must be an integer between 1 and 65535",
    );
    expect(invalidRes.errors).toContain("path must be a string");

    const invalidForwardToUrl = validateCliArgs({
      forwardTo: "invalid-url-string",
    });
    expect(invalidForwardToUrl.success).toBe(false);
    expect(invalidForwardToUrl.errors).toContain(
      'Invalid forwardTo URL format: "invalid-url-string"',
    );

    const invalidPortNan = validateCliArgs({ port: "abc" as any });
    expect(invalidPortNan.success).toBe(false);
    expect(invalidPortNan.errors).toContain(
      "port must be an integer between 1 and 65535",
    );
  });
});
