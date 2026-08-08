import { describe, expect, it, vi } from "vitest";
import { computeHmacSha256 } from "../src/core/crypto.js";
import { createWebhookHandler } from "../src/next.js";
import { bytesToHex } from "../src/utils/encoding.js";

describe("Next.js Route Handler Factory (createWebhookHandler)", () => {
  const secret = "github_next_secret";
  const bodyObj = { action: "opened", issue: { id: 42, title: "Bug report" } };
  const bodyStr = JSON.stringify(bodyObj);

  async function makeGitHubSignature() {
    const hmac = await computeHmacSha256(secret, bodyStr);
    return `sha256=${bytesToHex(hmac)}`;
  }

  it("should successfully verify request and call inner handler", async () => {
    const signature = await makeGitHubSignature();
    const mockHandler = vi.fn().mockResolvedValue(undefined);

    const routeHandler = createWebhookHandler("github", secret, mockHandler);

    const req = new Request("https://example.com/api/webhooks/github", {
      method: "POST",
      headers: {
        "x-hub-signature-256": signature,
        "content-type": "application/json",
      },
      body: bodyStr,
    });

    const response = await routeHandler(req);

    expect(mockHandler).toHaveBeenCalledTimes(1);
    const [payload, result, requestArg] = mockHandler.mock.calls[0];
    expect(payload).toEqual(bodyObj);
    expect(result.valid).toBe(true);
    expect(result.provider).toBe("github");
    expect(requestArg).toBe(req);

    expect(response.status).toBe(200);
    const json = await response.json();
    expect(json).toEqual({ received: true });
  });

  it("should handle non-JSON plain text body payloads", async () => {
    const textBody = "plain_text_payload";
    const hmac = await computeHmacSha256(secret, textBody);
    const signature = `sha256=${bytesToHex(hmac)}`;

    const mockHandler = vi.fn().mockResolvedValue(undefined);
    const routeHandler = createWebhookHandler("github", secret, mockHandler);

    const req = new Request("https://example.com/api/webhooks/github", {
      method: "POST",
      headers: { "x-hub-signature-256": signature },
      body: textBody,
    });

    const response = await routeHandler(req);
    expect(response.status).toBe(200);
    expect(mockHandler.mock.calls[0][0]).toBe("plain_text_payload");
  });

  it("should return 401 Response on invalid signature", async () => {
    const mockHandler = vi.fn();
    const routeHandler = createWebhookHandler("github", secret, mockHandler);

    const req = new Request("https://example.com/api/webhooks/github", {
      method: "POST",
      headers: { "x-hub-signature-256": "sha256=invalid_sig" },
      body: bodyStr,
    });

    const response = await routeHandler(req);
    expect(mockHandler).not.toHaveBeenCalled();
    expect(response.status).toBe(401);
    const json = await response.json();
    expect(json).toEqual({
      error: "SHA-256 signature mismatch",
      code: "INVALID_SIGNATURE",
    });
  });

  it("should invoke custom onError handler on signature failure or exception", async () => {
    const routeHandler = createWebhookHandler("github", secret, vi.fn(), {
      onError: async (result) => {
        return new Response(JSON.stringify({ customError: result.reason }), {
          status: 400,
          headers: { "Content-Type": "application/json" },
        });
      },
    });

    const req = new Request("https://example.com/api/webhooks/github", {
      method: "POST",
      headers: {},
      body: bodyStr,
    });

    const response = await routeHandler(req);
    expect(response.status).toBe(400);
    const json = await response.json();
    expect(json).toEqual({
      customError: 'Missing "x-hub-signature-256" or "x-hub-signature" header',
    });

    const throwingSecretResolver = () => {
      throw new Error("Secret lookup failed");
    };
    const routeHandlerException = createWebhookHandler(
      "github",
      throwingSecretResolver,
      vi.fn(),
      {
        onError: async (result) => {
          return new Response(JSON.stringify({ customError: result.reason }), {
            status: 503,
            headers: { "Content-Type": "application/json" },
          });
        },
      },
    );

    const responseException = await routeHandlerException(req);
    expect(responseException.status).toBe(503);
    const jsonException = await responseException.json();
    expect(jsonException).toEqual({ customError: "Secret lookup failed" });
  });
});
