import { afterEach, describe, expect, it, vi } from "vitest";
import { runCli } from "../src/cli/index.js";
import { verifyWebhook } from "../src/index.js";

// Runs `simulate`, captures the outgoing request, and checks verihook itself accepts it.
async function simulateAndCapture(args: string[]) {
  const logs: string[] = [];
  vi.spyOn(console, "log").mockImplementation((...a: unknown[]) => {
    logs.push(a.map(String).join(" "));
  });
  vi.spyOn(console, "warn").mockImplementation(() => {});
  const fetchSpy = vi
    .spyOn(globalThis, "fetch")
    .mockResolvedValue(new Response("{}", { status: 200 }));

  await runCli(["simulate", ...args]);

  const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
  return {
    url,
    headers: init.headers as Record<string, string>,
    body: init.body as string,
    logs,
  };
}

describe("CLI simulate produces verifiable webhooks", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it.each([
    ["square", "square_key"],
    ["zoom", "zoom_key"],
    ["linear", "linear_key"],
    ["razorpay", "razorpay_key"],
    ["generic", "generic_key"],
    ["stripe", "whsec_stripe_key"],
  ])("%s", async (provider, secret) => {
    const sent = await simulateAndCapture([provider, "--secret", secret]);
    const result = await verifyWebhook(
      provider,
      { headers: sent.headers, body: sent.body, url: sent.url },
      secret,
    );
    expect(result).toMatchObject({ valid: true });
  });

  it("discord signs with a generated key and prints the public key", async () => {
    const sent = await simulateAndCapture(["discord"]);
    const line = sent.logs.find((l) => l.includes("Discord public key"));
    const publicKey = line!.split(": ").pop()!.trim();
    const result = await verifyWebhook(
      "discord",
      { headers: sent.headers, body: sent.body },
      publicKey,
    );
    expect(result.valid).toBe(true);
  });

  it("refuses to simulate PayPal", async () => {
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    await runCli(["simulate", "paypal"]);
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(errSpy).toHaveBeenCalledWith(
      expect.stringContaining("cannot be simulated"),
    );
    process.exitCode = 0;
  });

  it("keeps '=' characters inside --flag=value arguments", async () => {
    const secret = "whsec_dGVzdF9zZWNyZXRfa2V5X2Zvcl9zdml4XzEyMw==";
    const sent = await simulateAndCapture([
      "svix",
      `--secret=${secret}`,
      "--url=http://localhost:3000/hooks?a=b",
    ]);
    expect(sent.url).toBe("http://localhost:3000/hooks?a=b");
    const result = await verifyWebhook(
      "svix",
      { headers: sent.headers, body: sent.body },
      secret,
    );
    expect(result.valid).toBe(true);
  });
});
