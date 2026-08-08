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
});
