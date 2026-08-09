import { EventEmitter } from "node:events";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { computeHmacSha256 } from "../src/core/crypto.js";
import { runCli, runListenServer } from "../src/cli/index.js";
import { bytesToHex } from "../src/utils/encoding.js";

let lastCapturedHandler: any = null;

vi.mock("node:http", async () => {
  const actual: any = await vi.importActual("node:http");
  const mockCreateServer = (handler: any) => {
    lastCapturedHandler = handler;
    return {
      listen: (_port: number, cb: () => void) => {
        if (cb) cb();
      },
      on: vi.fn(),
    };
  };

  return {
    ...actual,
    default: {
      ...actual.default,
      createServer: mockCreateServer,
    },
    createServer: mockCreateServer,
  };
});

describe("verihook Live Local Relay Proxy (npx verihook listen)", () => {
  beforeEach(() => {
    lastCapturedHandler = null;
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  function createMockReqRes(options: {
    method?: string;
    url?: string;
    headers?: Record<string, string>;
    body?: string;
  }) {
    const method = options.method || "POST";
    const url = options.url || "/";
    const headers = options.headers || {};
    const body = options.body || "";

    const req = new EventEmitter() as any;
    req.method = method;
    req.url = url;
    req.headers = headers;
    req[Symbol.asyncIterator] = async function* () {
      yield Buffer.from(body);
    };

    const res: any = {
      statusCode: 200,
      headers: {} as Record<string, string>,
      body: "",
      writeHead: vi
        .fn()
        .mockImplementation((status: number, hdrs?: Record<string, string>) => {
          res.statusCode = status;
          if (hdrs) res.headers = hdrs;
          return res;
        }),
      end: vi.fn().mockImplementation((chunk?: string) => {
        if (chunk) res.body += chunk;
        return res;
      }),
    };

    return { req, res };
  }

  it("should process incoming webhook, verify signature, and forward to targetUrl via fetch", async () => {
    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const secret = "github_secret_123";
    const testPayload = JSON.stringify({
      action: "opened",
      issue: { number: 101 },
    });
    const hmac = await computeHmacSha256(secret, testPayload);
    const signatureHeader = `sha256=${bytesToHex(hmac)}`;

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ status: "processed_by_app" }),
      headers: new Headers({ "content-type": "application/json" }),
    } as Response);

    await runListenServer({
      command: "listen",
      provider: "github",
      port: 8080,
      forwardTo: "http://localhost:3000/webhooks/github",
      secret,
    });

    expect(lastCapturedHandler).toBeTypeOf("function");

    const { req, res } = createMockReqRes({
      headers: {
        "content-type": "application/json",
        "x-hub-signature-256": signatureHeader,
      },
      body: testPayload,
    });

    await lastCapturedHandler(req, res);

    expect(fetchSpy).toHaveBeenCalledWith(
      "http://localhost:3000/webhooks/github",
      expect.objectContaining({
        method: "POST",
        body: testPayload,
      }),
    );
    expect(res.statusCode).toBe(200);
    expect(res.body).toBe(JSON.stringify({ status: "processed_by_app" }));
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining("SIGNATURE MATCH"),
    );

    consoleSpy.mockRestore();
    fetchSpy.mockRestore();
  });

  it("should forward webhook with unverified notice when no secret is provided", async () => {
    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      status: 200,
      text: async () => "OK",
      headers: new Headers(),
    } as Response);

    await runListenServer({
      command: "listen",
      provider: "stripe",
      port: 8080,
      forwardTo: "http://localhost:3000/webhooks/stripe",
    });

    const { req, res } = createMockReqRes({
      body: JSON.stringify({ event: "charge.succeeded" }),
    });

    await lastCapturedHandler(req, res);

    expect(res.statusCode).toBe(200);
    expect(res.body).toBe("OK");
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining("UNVERIFIED"),
    );

    consoleSpy.mockRestore();
    fetchSpy.mockRestore();
  });

  it("should handle verification mismatch and log signature failure", async () => {
    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      status: 200,
      text: async () => "OK",
      headers: new Headers(),
    } as Response);

    await runListenServer({
      command: "listen",
      provider: "github",
      secret: "correct_secret",
      forwardTo: "http://localhost:3000/webhooks/github",
    });

    const { req, res } = createMockReqRes({
      headers: { "x-hub-signature-256": "sha256=invalid" },
      body: JSON.stringify({ test: "data" }),
    });

    await lastCapturedHandler(req, res);

    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining("INVALID SIGNATURE"),
    );
    expect(res.statusCode).toBe(200);

    consoleSpy.mockRestore();
    fetchSpy.mockRestore();
  });

  it("should return 502 Bad Gateway on forwarding fetch exception", async () => {
    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockRejectedValueOnce(new TypeError("fetch failed: ECONNREFUSED"));

    await runListenServer({
      command: "listen",
      provider: "stripe",
      forwardTo: "http://localhost:59998/webhooks",
    });

    const { req, res } = createMockReqRes({
      body: JSON.stringify({ ping: true }),
    });

    await lastCapturedHandler(req, res);

    expect(res.statusCode).toBe(502);
    expect(JSON.parse(res.body)).toEqual({
      error: "Bad Gateway",
      message: "Forwarding failed: fetch failed: ECONNREFUSED",
    });

    consoleSpy.mockRestore();
    errSpy.mockRestore();
    fetchSpy.mockRestore();
  });

  it("should handle short secret header redaction (<12 chars) and verifyWebhook exceptions in runListenServer", async () => {
    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: true,
      status: 200,
      text: async () => "OK",
      headers: new Headers(),
    } as Response);

    await runListenServer({
      command: "listen",
      provider: "unsupported_provider" as any,
      secret: "short_secret",
      forwardTo: "http://localhost:3000/webhooks/unsupported",
    });

    const { req, res } = createMockReqRes({
      headers: { "x-signature": "short_sig" },
      body: JSON.stringify({ event: "test" }),
    });

    await lastCapturedHandler(req, res);

    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining("INVALID SIGNATURE"),
    );
    expect(consoleSpy).toHaveBeenCalledWith(
      "  📋 Headers:",
      expect.objectContaining({ "x-signature": "[REDACTED]" }),
    );

    consoleSpy.mockRestore();
    fetchSpy.mockRestore();
  });

  it("should enforce SSRF protection on forwardTo metadata target URL", async () => {
    await expect(
      runListenServer({
        command: "listen",
        provider: "github",
        forwardTo: "http://169.254.169.254/latest/meta-data",
      }),
    ).rejects.toThrow("SSRF Prevention");
  });

  it("should handle GET requests, header arrays, string body chunks, payload truncation, and non-ok target responses", async () => {
    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce({
      ok: false,
      status: 404,
      text: async () => "Not Found",
      headers: new Headers({ "content-type": "text/plain" }),
    } as Response);

    await runListenServer({
      command: "listen",
      provider: "stripe",
      forwardTo: "http://localhost:3000/webhooks/stripe",
    });

    const longPayload = "x".repeat(350);
    const { req, res } = createMockReqRes({
      method: "GET",
      headers: { "x-multi-value": ["val1", "val2"] as any },
      body: longPayload,
    });
    // Override asyncIterator to yield string chunk
    req[Symbol.asyncIterator] = async function* () {
      yield longPayload;
    };

    await lastCapturedHandler(req, res);

    expect(fetchSpy).toHaveBeenCalledWith(
      "http://localhost:3000/webhooks/stripe",
      expect.objectContaining({
        method: "GET",
        body: undefined,
      }),
    );
    expect(res.statusCode).toBe(404);
    expect(res.body).toBe("Not Found");
    expect(consoleSpy).toHaveBeenCalledWith(
      "  📦 Body:",
      expect.stringContaining("... [truncated]"),
    );
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining("⚠️ RESPONDED"),
    );

    consoleSpy.mockRestore();
    fetchSpy.mockRestore();
  });

  it("should parse CLI listen flags correctly", async () => {
    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    await runCli([
      "listen",
      "stripe",
      "--forward-to=http://localhost:3000/webhooks/stripe",
      "--port=8085",
      "--secret=whsec_test_secret",
      "--allow-remote",
    ]);

    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining("verihook Live Local Relay Proxy"),
    );

    consoleSpy.mockRestore();
  });
});
