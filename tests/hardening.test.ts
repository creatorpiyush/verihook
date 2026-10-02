import { afterEach, describe, expect, it, vi } from "vitest";
import pkg from "../package.json";
import { runCli } from "../src/cli/index.js";
import {
  computeHmacSha1,
  computeHmacSha256,
  computeSha256,
} from "../src/core/crypto.js";
import {
  registerProvider,
  verifyMetaChallenge,
  verifyWebhook,
} from "../src/index.js";
import { bytesToBase64, bytesToHex } from "../src/utils/encoding.js";

const now = 1700000000;

async function twilioSign(secret: string, data: string) {
  return bytesToBase64(await computeHmacSha1(secret, data));
}

describe("signed URL resolution (Twilio / Square behind Express)", () => {
  const secret = "twilio_token";
  const formBody = "Body=Hello&From=%2B15551234567";
  const formSigned =
    "https://hooks.example.com/webhooks/twilio" +
    "BodyHello" +
    "From+15551234567";

  it("rebuilds the public URL from forwarded headers when only a path is available", async () => {
    const signature = await twilioSign(secret, formSigned);
    const result = await verifyWebhook(
      "twilio",
      {
        headers: {
          "x-twilio-signature": signature,
          "content-type": "application/x-www-form-urlencoded",
          host: "internal:3000",
          "x-forwarded-host": "hooks.example.com",
          "x-forwarded-proto": "https",
        },
        body: formBody,
        originalUrl: "/webhooks/twilio",
      },
      secret,
    );
    expect(result.valid).toBe(true);
  });

  it("uses req.protocol for plain-http local development", async () => {
    const signature = await twilioSign(
      secret,
      formSigned.replace("https://hooks.example.com", "http://localhost:3000"),
    );
    const result = await verifyWebhook(
      "twilio",
      {
        headers: {
          "x-twilio-signature": signature,
          "content-type": "application/x-www-form-urlencoded",
          host: "localhost:3000",
        },
        body: formBody,
        originalUrl: "/webhooks/twilio",
        protocol: "http",
      },
      secret,
    );
    expect(result.valid).toBe(true);
  });

  it("accepts signatures made with or without the default port", async () => {
    const signature = await twilioSign(
      secret,
      formSigned.replace("hooks.example.com", "hooks.example.com:443"),
    );
    const result = await verifyWebhook(
      "twilio",
      {
        headers: {
          "x-twilio-signature": signature,
          "content-type": "application/x-www-form-urlencoded",
        },
        body: formBody,
        url: "https://hooks.example.com/webhooks/twilio",
      },
      secret,
    );
    expect(result.valid).toBe(true);
  });

  it("signs JSON bodies against the exact URL string (no URL re-serialization)", async () => {
    const body = JSON.stringify({ CallSid: "CA123" });
    const hash = bytesToHex(await computeSha256(body));
    const url = `https://hooks.example.com?bodySHA256=${hash}`;
    const result = await verifyWebhook(
      "twilio",
      {
        headers: {
          "x-twilio-signature": await twilioSign(secret, url),
          "content-type": "application/json",
        },
        body,
        url,
      },
      secret,
    );
    expect(result.valid).toBe(true);
  });

  it("resolves Square's signed URL from the host header", async () => {
    const body = JSON.stringify({ type: "payment.created" });
    const signature = bytesToBase64(
      await computeHmacSha256(
        "sq_key",
        "https://shop.example.com/webhooks/square" + body,
      ),
    );
    const result = await verifyWebhook(
      "square",
      {
        headers: {
          "x-square-hmacsha256-signature": signature,
          host: "shop.example.com",
        },
        body,
        originalUrl: "/webhooks/square",
      },
      "sq_key",
    );
    expect(result.valid).toBe(true);
  });
});

describe("provider registry", () => {
  it("does not resolve Object.prototype members as providers", async () => {
    for (const name of ["constructor", "__proto__", "toString"]) {
      const result = await verifyWebhook(name, { headers: {}, body: "" }, "s");
      expect(result.code).toBe("UNSUPPORTED_PROVIDER");
    }
  });

  it("refuses reserved provider names", () => {
    expect(() =>
      registerProvider({ name: "__proto__", verify: vi.fn() }),
    ).toThrow(/Invalid provider name/);
  });

  it("maps foreign error codes to UNKNOWN_ERROR", async () => {
    registerProvider({
      name: "throws-node-error",
      async verify() {
        throw Object.assign(new Error("boom"), { code: "ERR_SOCKET" });
      },
    });
    const result = await verifyWebhook(
      "throws-node-error",
      { headers: {}, body: "" },
      "s",
    );
    expect(result.code).toBe("UNKNOWN_ERROR");
  });
});

describe("secret rotation (multiple signatures)", () => {
  const body = JSON.stringify({ id: "evt_rot" });

  it("Paddle accepts any matching h= value", async () => {
    const good = bytesToHex(await computeHmacSha256("new", `${now}:${body}`));
    const result = await verifyWebhook(
      "paddle",
      {
        headers: {
          "paddle-signature": `ts=${now};h=${"0".repeat(64)};h=${good}`,
        },
        body,
      },
      "new",
      { now },
    );
    expect(result.valid).toBe(true);
  });

  it("WorkOS accepts any matching v1= value", async () => {
    const good = bytesToHex(await computeHmacSha256("new", `${now}.${body}`));
    const result = await verifyWebhook(
      "workos",
      {
        headers: {
          "workos-signature": `t=${now},v1=${"0".repeat(64)},v1=${good}`,
        },
        body,
      },
      "new",
      { now },
    );
    expect(result.valid).toBe(true);
  });
});

describe("Meta challenge", () => {
  it("accepts the matching token and rejects others", () => {
    const query = { "hub.mode": "subscribe", "hub.challenge": "c1" };
    expect(
      verifyMetaChallenge({ ...query, "hub.verify_token": "tok" }, "tok"),
    ).toEqual({ valid: true, challenge: "c1" });
    expect(
      verifyMetaChallenge({ ...query, "hub.verify_token": "tok2" }, "tok")
        .valid,
    ).toBe(false);
    expect(verifyMetaChallenge(query, "").valid).toBe(false);
  });
});

describe("CLI output", () => {
  afterEach(() => vi.restoreAllMocks());

  it("shell-quotes --curl output so quotes in the payload stay literal", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    await runCli(["simulate", "generic", "--event", "it's", "--curl"]);
    const line = String(logSpy.mock.calls.at(-1)?.[0]);
    expect(line).toContain(`it'\\''s`);
    expect(line).toMatch(
      /^curl -X POST 'http:\/\/localhost:3000\/webhooks\/generic' -H '/,
    );
  });

  it("reports the package version in help output", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    await runCli([]);
    expect(String(logSpy.mock.calls[0][0])).toContain(`(v${pkg.version})`);
  });
});
