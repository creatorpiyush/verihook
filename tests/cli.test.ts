import { beforeEach, describe, expect, it, vi } from "vitest";
import { runCli } from "../src/cli/index.js";

describe("verihook CLI Simulator", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("should print help menu when no provider is passed", async () => {
    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    await runCli([]);
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining("npx verihook simulate"),
    );
    consoleSpy.mockRestore();
  });

  it("should generate valid cURL command with --curl flag for Stripe", async () => {
    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    await runCli(["simulate", "stripe", "--curl"]);
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining("curl -X POST"),
    );
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining("stripe-signature"),
    );
    consoleSpy.mockRestore();
  });

  it("should handle Twilio simulation with query parameters on target URL", async () => {
    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    await runCli([
      "simulate",
      "twilio",
      "--url",
      "http://127.0.0.1:3000/webhook?env=dev",
      "--curl",
    ]);
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining("http://127.0.0.1:3000/webhook?env=dev"),
    );
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining("x-twilio-signature"),
    );
    consoleSpy.mockRestore();
  });

  it("should generate cURL for GitHub simulation with custom event", async () => {
    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    await runCli(["simulate", "github", "--event", "pull_request", "--curl"]);
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining("x-hub-signature-256"),
    );
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining("pull_request"),
    );
    consoleSpy.mockRestore();
  });

  it("should support cURL generation for all 20+ providers with valid secrets", async () => {
    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const providers = [
      "meta",
      "whatsapp",
      "twitter",
      "x",
      "lemonsqueezy",
      "paddle",
      "pagerduty",
      "webflow",
      "workos",
      "slack",
      "clerk",
      "resend",
      "discord",
      "square",
      "linear",
      "razorpay",
      "zoom",
      "generic",
    ];

    const validBase64Secret = "whsec_dGVzdF9zZWNyZXRfa2V5X2Zvcl9zdml4XzEyMw==";

    for (const p of providers) {
      await runCli(["simulate", p, "--secret", validBase64Secret, "--curl"]);
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining("curl -X POST"),
      );
    }

    consoleSpy.mockRestore();
  });

  it("should handle successful 200 JSON POST responses and 500 plain text error responses", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    const fetchSpy200 = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      status: 200,
      text: async () => JSON.stringify({ success: true }),
    } as Response);

    await runCli([
      "simulate",
      "stripe",
      "--url",
      "http://127.0.0.1:3000/webhook",
    ]);
    expect(logSpy).toHaveBeenCalledWith(
      expect.stringContaining("SUCCESS [HTTP 200]"),
    );

    const fetchSpy500 = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      status: 500,
      text: async () => "Internal Server Failure",
    } as Response);

    await runCli([
      "simulate",
      "stripe",
      "--url",
      "http://127.0.0.1:3000/webhook",
    ]);
    expect(logSpy).toHaveBeenCalledWith(
      expect.stringContaining("FAILED [HTTP 500]"),
    );

    fetchSpy200.mockRestore();
    fetchSpy500.mockRestore();
    logSpy.mockRestore();
  });

  it("should output simulation details and handle connection errors when sending POST", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockRejectedValue(new TypeError("connect ECONNREFUSED 127.0.0.1:59999"));

    await runCli([
      "simulate",
      "stripe",
      "--url",
      "http://127.0.0.1:59999/webhook",
    ]);

    expect(logSpy).toHaveBeenCalledWith(
      expect.stringContaining("Simulating signed STRIPE webhook"),
    );
    expect(errSpy).toHaveBeenCalledWith(
      expect.stringContaining(
        "Could not connect to http://127.0.0.1:59999/webhook:",
      ),
      expect.anything(),
    );
  });
});
