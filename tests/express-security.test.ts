import { describe, expect, it } from "vitest";
import { verihookExpress } from "../src/middleware/express.js";

describe("Express Middleware Security Hardening", () => {
  it("should reject unparsed stream body exceeding maxBodySize with 413 Payload Too Large", async () => {
    const middleware = verihookExpress("github", "secret_123", {
      maxBodySize: 100, // 100 bytes limit for test
    });

    let responseStatus: number | undefined;
    let responseJson: unknown;
    const headers: Record<string, string> = {};

    const mockReq = {
      body: undefined,
      on: () => {},
      headers: {
        "x-hub-signature-256": "sha256=test",
      },
      async *[Symbol.asyncIterator]() {
        yield Buffer.alloc(80, "a");
        yield Buffer.alloc(80, "b"); // Exceeds 100 bytes!
      },
    };

    const mockRes = {
      status(code: number) {
        responseStatus = code;
        return this;
      },
      json(body: unknown) {
        responseJson = body;
        return this;
      },
      setHeader(name: string, value: string) {
        headers[name] = value;
        return this;
      },
    };

    let nextCalled = false;
    const mockNext = () => {
      nextCalled = true;
    };

    await middleware(mockReq as any, mockRes as any, mockNext as any);

    expect(responseStatus).toBe(413);
    expect((responseJson as any)?.code).toBe("PAYLOAD_TOO_LARGE");
    expect(headers["X-Content-Type-Options"]).toBe("nosniff");
    expect(headers["X-Frame-Options"]).toBe("DENY");
    expect(nextCalled).toBe(false);
  });
});
