import { describe, expect, it } from "vitest";
import { generateKeyPairSync, sign } from "node:crypto";
import crypto from "node:crypto";
import {
  computeHmacSha256,
  createWebhookHandler,
  registerProvider,
  verifyClerk,
  verifyDiscord,
  verifyGitHub,
  verifyLemonSqueezy,
  verifyLinear,
  verifyMeta,
  verifyMetaChallenge,
  verifyPaddle,
  verifyPagerDuty,
  verifyPayPal,
  verifyRazorpay,
  verifyResend,
  verifyShopify,
  verifySlack,
  verifySquare,
  verifyStripe,
  verifySvix,
  verifyTwilio,
  verifyWebflow,
  verifyWebhook,
  verifyWebhookOrThrow,
  verifyWorkOS,
  verifyX,
  verifyZoom,
  verihookExpress,
} from "../src/index.js";
import { runCli } from "../src/cli/index.js";
import {
  base64ToBytes,
  bytesToBase64,
  bytesToHex,
} from "../src/utils/encoding.js";

describe("Comprehensive End-to-End Regression Suite", () => {
  const ts = Math.floor(Date.now() / 1000);

  it("should verify all 20+ signature algorithms across providers", async () => {
    // Stripe
    const stripeSecret = "whsec_stripe_test";
    const stripeBody = JSON.stringify({ id: "evt_stripe_100" });
    const stripeHmac = bytesToHex(
      await computeHmacSha256(stripeSecret, `${ts}.${stripeBody}`),
    );
    const stripeRes = await verifyStripe(
      {
        headers: { "stripe-signature": `t=${ts},v1=${stripeHmac}` },
        body: stripeBody,
      },
      stripeSecret,
      { now: ts },
    );
    expect(stripeRes.valid).toBe(true);

    // GitHub
    const ghSecret = "gh_secret_999";
    const ghBody = JSON.stringify({ action: "push" });
    const ghHmac = bytesToHex(await computeHmacSha256(ghSecret, ghBody));
    const ghRes = await verifyGitHub(
      { headers: { "x-hub-signature-256": `sha256=${ghHmac}` }, body: ghBody },
      ghSecret,
    );
    expect(ghRes.valid).toBe(true);

    // Shopify
    const shopifySecret = "shpss_secret_123";
    const shopifyBody = JSON.stringify({ id: 1001 });
    const shopifyHmac = bytesToBase64(
      await computeHmacSha256(shopifySecret, shopifyBody),
    );
    const shopifyRes = await verifyShopify(
      { headers: { "x-shopify-hmac-sha256": shopifyHmac }, body: shopifyBody },
      shopifySecret,
    );
    expect(shopifyRes.valid).toBe(true);

    // Slack
    const slackSecret = "slack_sec_888";
    const slackBody = "command=%2Ftest";
    const slackSigBase = `v0:${ts}:${slackBody}`;
    const slackHmac = bytesToHex(
      await computeHmacSha256(slackSecret, slackSigBase),
    );
    const slackRes = await verifySlack(
      {
        headers: {
          "x-slack-signature": `v0=${slackHmac}`,
          "x-slack-request-timestamp": String(ts),
        },
        body: slackBody,
      },
      slackSecret,
      { now: ts },
    );
    expect(slackRes.valid).toBe(true);

    // Svix / Resend / Clerk
    const svixSecret = "whsec_dGVzdF9zZWNyZXRfa2V5X2Zvcl9zdml4XzEyMw==";
    const svixBody = JSON.stringify({ event: "user.created" });
    const msgId = "msg_reg_100";
    const svixToSign = `${msgId}.${ts}.${svixBody}`;
    const svixHmac = bytesToBase64(
      await computeHmacSha256(
        base64ToBytes("dGVzdF9zZWNyZXRfa2V5X2Zvcl9zdml4XzEyMw=="),
        svixToSign,
      ),
    );
    const svixRes = await verifySvix(
      {
        headers: {
          "svix-id": msgId,
          "svix-timestamp": String(ts),
          "svix-signature": `v1,${svixHmac}`,
        },
        body: svixBody,
      },
      svixSecret,
      { now: ts },
    );
    expect(svixRes.valid).toBe(true);

    expect(
      (
        await verifyResend(
          {
            headers: {
              "svix-id": msgId,
              "svix-timestamp": String(ts),
              "svix-signature": `v1,${svixHmac}`,
            },
            body: svixBody,
          },
          svixSecret,
          { now: ts },
        )
      ).valid,
    ).toBe(true);
    expect(
      (
        await verifyClerk(
          {
            headers: {
              "svix-id": msgId,
              "svix-timestamp": String(ts),
              "svix-signature": `v1,${svixHmac}`,
            },
            body: svixBody,
          },
          svixSecret,
          { now: ts },
        )
      ).valid,
    ).toBe(true);

    // Meta & Challenge
    const metaSecret = "meta_app_secret_123";
    const metaBody = JSON.stringify({ object: "page" });
    const metaHmac = bytesToHex(await computeHmacSha256(metaSecret, metaBody));
    expect(
      (
        await verifyMeta(
          {
            headers: { "x-hub-signature-256": `sha256=${metaHmac}` },
            body: metaBody,
          },
          metaSecret,
        )
      ).valid,
    ).toBe(true);
    expect(
      verifyMetaChallenge(
        "http://127.0.0.1/webhook?hub.mode=subscribe&hub.challenge=test_challenge&hub.verify_token=my_token",
        "my_token",
      ).challenge,
    ).toBe("test_challenge");

    // Discord Ed25519
    const { publicKey: discordPubKeyObj, privateKey: discordPrivKeyObj } =
      generateKeyPairSync("ed25519");
    const publicSpkiDer = discordPubKeyObj.export({
      format: "der",
      type: "spki",
    }) as Buffer;
    const discordPubKeyHex = publicSpkiDer
      .subarray(publicSpkiDer.length - 32)
      .toString("hex");
    const discordBody = JSON.stringify({ type: 1 });

    const signatureBytes = sign(
      null,
      Buffer.from(`${ts}${discordBody}`, "utf-8"),
      discordPrivKeyObj,
    );

    const discordReq = {
      headers: {
        "x-signature-ed25519": signatureBytes.toString("hex"),
        "x-signature-timestamp": String(ts),
      },
      body: discordBody,
    };

    const discordRes = await verifyDiscord(discordReq, discordPubKeyHex, {
      now: ts,
      tolerance: 300,
    });
    expect(discordRes.valid).toBe(true);

    // Twitter / X
    const twitterSecret = "tw_consumer_secret";
    const twitterBody = JSON.stringify({ for_user_id: "123" });
    const twitterHmac = bytesToBase64(
      await computeHmacSha256(twitterSecret, twitterBody),
    );
    expect(
      (
        await verifyX(
          {
            headers: {
              "x-twitter-webhooks-signature": `sha256=${twitterHmac}`,
            },
            body: twitterBody,
          },
          twitterSecret,
        )
      ).valid,
    ).toBe(true);

    // Remaining Providers
    expect(
      (
        await verifyLemonSqueezy(
          {
            headers: {
              "x-signature": bytesToHex(await computeHmacSha256("sec", "raw")),
            },
            body: "raw",
          },
          "sec",
        )
      ).valid,
    ).toBe(true);
    expect(
      (
        await verifyPaddle(
          {
            headers: {
              "paddle-signature": `ts=${ts};h=${bytesToHex(await computeHmacSha256("sec", `${ts}:raw`))}`,
            },
            body: "raw",
          },
          "sec",
          { now: ts },
        )
      ).valid,
    ).toBe(true);
    expect(
      (
        await verifyPagerDuty(
          {
            headers: {
              "x-pagerduty-signature": `v1=${bytesToHex(await computeHmacSha256("sec", "raw"))}`,
            },
            body: "raw",
          },
          "sec",
        )
      ).valid,
    ).toBe(true);
    expect(
      (
        await verifyWebflow(
          {
            headers: {
              "x-webflow-signature": bytesToHex(
                await computeHmacSha256("sec", "raw"),
              ),
            },
            body: "raw",
          },
          "sec",
        )
      ).valid,
    ).toBe(true);
    expect(
      (
        await verifyWorkOS(
          {
            headers: {
              "workos-signature": `t=${ts},v1=${bytesToHex(await computeHmacSha256("sec", `${ts}.raw`))}`,
            },
            body: "raw",
          },
          "sec",
          { now: ts },
        )
      ).valid,
    ).toBe(true);
    expect(
      (
        await verifyLinear(
          {
            headers: {
              "linear-signature": bytesToHex(
                await computeHmacSha256("sec", "raw"),
              ),
            },
            body: "raw",
          },
          "sec",
        )
      ).valid,
    ).toBe(true);
    expect(
      (
        await verifyRazorpay(
          {
            headers: {
              "x-razorpay-signature": bytesToHex(
                await computeHmacSha256("sec", "raw"),
              ),
            },
            body: "raw",
          },
          "sec",
        )
      ).valid,
    ).toBe(true);
    expect(
      (
        await verifySquare(
          {
            headers: {
              "x-square-hmacsha256-signature": bytesToBase64(
                await computeHmacSha256("sec", "http://127.0.0.1/rawraw"),
              ),
            },
            body: "raw",
            url: "http://127.0.0.1/raw",
          },
          "sec",
        )
      ).valid,
    ).toBe(true);
    expect(
      (
        await verifyZoom(
          {
            headers: {
              "x-zm-signature": `v0=${bytesToHex(await computeHmacSha256("sec", `v0:${ts}:raw`))}`,
              "x-zm-request-timestamp": String(ts),
            },
            body: "raw",
          },
          "sec",
          { now: ts },
        )
      ).valid,
    ).toBe(true);
  });

  it("should verify negative paths and error codes", async () => {
    const invalidSigRes = await verifyStripe(
      { headers: { "stripe-signature": `t=${ts},v1=bad_sig` }, body: "raw" },
      "sec",
      { now: ts },
    );
    expect(invalidSigRes.valid).toBe(false);
    expect(invalidSigRes.code).toBe("INVALID_SIGNATURE");

    const missingSecretRes = await verifyStripe(
      { headers: {}, body: "raw" },
      "",
    );
    expect(missingSecretRes.valid).toBe(false);
    expect(missingSecretRes.code).toBe("INVALID_SECRET");

    const unsupportedRes = await verifyWebhook(
      "unknown_prov" as any,
      { headers: {}, body: "raw" },
      "sec",
    );
    expect(unsupportedRes.valid).toBe(false);
    expect(unsupportedRes.code).toBe("UNSUPPORTED_PROVIDER");

    await expect(
      verifyWebhookOrThrow("stripe", { headers: {}, body: "raw" }, "sec"),
    ).rejects.toThrow();
  });

  it("should verify custom plugin registration", async () => {
    registerProvider({
      name: "reg-custom-provider",
      async verify(req, secretKey) {
        return {
          valid: req.headers["x-custom-sig"] === secretKey,
          provider: "reg-custom-provider",
        };
      },
    });

    const customRes = await verifyWebhook(
      "reg-custom-provider" as any,
      { headers: { "x-custom-sig": "pass_123" }, body: "raw" },
      "pass_123",
    );
    expect(customRes.valid).toBe(true);
    expect(customRes.provider).toBe("reg-custom-provider");
  });

  it("should verify Express and Next.js middleware adapters", async () => {
    const stripeSecret = "whsec_stripe_test";
    const stripeBody = JSON.stringify({ id: "evt_stripe_100" });
    const stripeHmac = bytesToHex(
      await computeHmacSha256(stripeSecret, `${ts}.${stripeBody}`),
    );

    const expressMiddleware = verihookExpress("stripe", stripeSecret, {
      now: ts,
    });
    const mockReq: any = {
      headers: { "stripe-signature": `t=${ts},v1=${stripeHmac}` },
      body: stripeBody,
    };
    const mockRes: any = {
      status: () => mockRes,
      json: () => mockRes,
      setHeader: () => mockRes,
    };
    let nextCalled = false;
    await expressMiddleware(mockReq, mockRes, () => {
      nextCalled = true;
    });
    expect(nextCalled).toBe(true);
    expect(mockReq.verihook.valid).toBe(true);

    const nextHandler = createWebhookHandler(
      "stripe",
      stripeSecret,
      async (payload) => {
        return new Response(JSON.stringify({ status: "ok", payload }), {
          status: 200,
        });
      },
      { now: ts },
    );
    const nextReq = new Request("http://127.0.0.1:3000/api/webhook", {
      method: "POST",
      headers: { "stripe-signature": `t=${ts},v1=${stripeHmac}` },
      body: stripeBody,
    });
    const nextRes = await nextHandler(nextReq);
    expect(nextRes.status).toBe(200);
  });

  it("should verify CLI simulator output generation", async () => {
    const cliLogs: string[] = [];
    const origLog = console.log;
    console.log = (msg: string) => cliLogs.push(msg);

    await runCli([
      "simulate",
      "stripe",
      "--url",
      "http://127.0.0.1:3000/webhook",
      "--curl",
    ]);
    console.log = origLog;

    expect(
      cliLogs.some(
        (l) => l.includes("curl -X POST") && l.includes("stripe-signature"),
      ),
    ).toBe(true);
  });
});
