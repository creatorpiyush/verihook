import { describe, expect, it } from "vitest";
import * as MainIndex from "../src/index.js";
import * as ExpressIndex from "../src/express.js";
import * as NextIndex from "../src/next.js";

describe("Package Entry Point Exports", () => {
  it("should export core verifiers and utilities from index.ts", () => {
    expect(MainIndex.verifyWebhook).toBeDefined();
    expect(MainIndex.verifyWebhookOrThrow).toBeDefined();
    expect(MainIndex.verifyStripe).toBeDefined();
    expect(MainIndex.verifyGitHub).toBeDefined();
    expect(MainIndex.timingSafeEqual).toBeDefined();
    expect(MainIndex.computeHmacSha256).toBeDefined();
    expect(MainIndex.WebhookVerificationError).toBeDefined();
    expect(MainIndex.WebhookErrorCode).toBeDefined();
    expect(MainIndex.registerProvider).toBeDefined();
  });

  it("should export Express middleware from express.ts", () => {
    expect(ExpressIndex.verihookExpress).toBeDefined();
  });

  it("should export Next.js handler from next.ts", () => {
    expect(NextIndex.createWebhookHandler).toBeDefined();
  });
});
