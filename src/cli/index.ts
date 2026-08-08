#!/usr/bin/env node
import fs from "node:fs";
import process from "node:process";
import { fileURLToPath } from "node:url";
import {
  computeHmacSha1,
  computeHmacSha256,
  computeSha256,
} from "../core/crypto.js";
import { ParsedCliArgs, validateCliArgs } from "../schemas/index.js";
import { base64ToBytes, bytesToBase64, bytesToHex } from "../utils/encoding.js";

function parseArgs(args: string[]): ParsedCliArgs {
  const rawResult: Record<string, unknown> = {};
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (
      arg === "simulate" &&
      i + 1 < args.length &&
      !args[i + 1].startsWith("-")
    ) {
      rawResult.provider = args[i + 1].toLowerCase();
      i++;
    } else if (arg.startsWith("--url=")) {
      rawResult.url = arg.split("=")[1];
    } else if (arg === "--url" && i + 1 < args.length) {
      rawResult.url = args[i + 1];
      i++;
    } else if (arg.startsWith("--secret=")) {
      rawResult.secret = arg.split("=")[1];
    } else if (arg === "--secret" && i + 1 < args.length) {
      rawResult.secret = args[i + 1];
      i++;
    } else if (arg.startsWith("--event=")) {
      rawResult.event = arg.split("=")[1];
    } else if (arg === "--event" && i + 1 < args.length) {
      rawResult.event = args[i + 1];
      i++;
    } else if (arg === "--curl") {
      rawResult.printCurl = true;
    } else if (arg === "--allow-remote") {
      rawResult.allowRemote = true;
    }
  }
  const validation = validateCliArgs(rawResult);
  if (!validation.success) {
    console.error("❌ Invalid CLI parameters:", validation.errors.join(", "));
    process.exit(1);
  }
  return validation.data;
}

const BLOCKED_HOSTNAMES = new Set([
  "169.254.169.254",
  "169.254.170.2",
  "168.63.129.16",
  "100.100.100.200",
  "metadata.google.internal",
  "metadata.tencentyun.com",
  "169.254.169.254.ipv4.super-int.sub",
  "instance-data",
]);

function isPrivateNetworkHost(hostname: string): boolean {
  const cleanHost = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  const ipMatch = cleanHost.match(
    /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/,
  );

  if (!ipMatch) {
    return cleanHost === "localhost";
  }

  const [_, o1, o2] = ipMatch.map(Number);

  // 10.0.0.0/8
  if (o1 === 10) return true;
  // 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
  if (o1 === 172 && o2 >= 16 && o2 <= 31) return true;
  // 192.168.0.0/16
  if (o1 === 192 && o2 === 168) return true;
  // 127.0.0.0/8 (Loopback)
  if (o1 === 127) return true;
  // 100.64.0.0/10 (Carrier-Grade NAT)
  if (o1 === 100 && o2 >= 64 && o2 <= 127) return true;

  return false;
}

function isBlockedSsrfHost(hostname: string): boolean {
  const cleanHost = hostname.toLowerCase().replace(/^\[|\]$/g, "");

  if (BLOCKED_HOSTNAMES.has(cleanHost)) {
    return true;
  }

  // Check 169.254.0.0/16 Link-Local subnet range (AWS/GCP/Azure/OpenStack metadata block)
  const ipMatch = cleanHost.match(
    /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/,
  );
  if (ipMatch) {
    const oct1 = Number(ipMatch[1]);
    const oct2 = Number(ipMatch[2]);
    if (oct1 === 169 && oct2 === 254) {
      return true;
    }
  }

  // Check octal IP notation (e.g. 0251.0376.0251.0376 = 169.254.169.254)
  const octalMatch = cleanHost.match(/^0[0-7]+\.0[0-7]+\.0[0-7]+\.0[0-7]+$/);
  if (octalMatch) {
    const parts = cleanHost.split(".").map((p) => parseInt(p, 8));
    if (parts[0] === 169 && parts[1] === 254) {
      return true;
    }
  }

  // Check IPv4-mapped IPv6 (::ffff:169.254.x.x) or fe80:: link-local IPv6
  if (
    cleanHost.startsWith("::ffff:169.254.") ||
    cleanHost.startsWith("fe80:") ||
    cleanHost.startsWith("::ffff:a9fe:")
  ) {
    return true;
  }

  // Check decimal representation of 169.254.169.254 (2852039166) or hex representations (0xa9fea9fe)
  if (
    cleanHost === "2852039166" ||
    cleanHost === "0xa9fea9fe" ||
    cleanHost === "0xa9.0xfe.0xa9.0xfe"
  ) {
    return true;
  }

  return false;
}

function validateUrlForSsrf(urlStr: string, allowRemote: boolean): URL {
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(urlStr);
  } catch {
    throw new Error(`Invalid target URL: ${urlStr}`);
  }

  if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
    throw new Error(
      `Forbidden URL protocol "${parsedUrl.protocol}". Only http: and https: are allowed.`,
    );
  }

  const hostname = parsedUrl.hostname.toLowerCase();

  if (isBlockedSsrfHost(hostname)) {
    throw new Error(
      `SSRF Prevention: Requests to cloud metadata host "${hostname}" are strictly blocked.`,
    );
  }

  const isAllowedRemote =
    allowRemote || process.env.VERIHOOK_ALLOW_REMOTE === "true";
  const isLocal = isPrivateNetworkHost(hostname);

  if (!isLocal && !isAllowedRemote) {
    console.warn(
      `⚠️ Warning: Targeting non-local host "${hostname}". Pass --allow-remote or set VERIHOOK_ALLOW_REMOTE=true to disable this notice.`,
    );
  }

  return parsedUrl;
}

function redactHeaders(
  headers: Record<string, string>,
): Record<string, string> {
  const redacted: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    const lower = key.toLowerCase();
    if (
      lower.includes("signature") ||
      lower.includes("token") ||
      lower.includes("auth") ||
      lower.includes("secret") ||
      lower.includes("svix-")
    ) {
      redacted[key] =
        value.length > 12 ? `${value.slice(0, 8)}...[REDACTED]` : "[REDACTED]";
    } else {
      redacted[key] = value;
    }
  }
  return redacted;
}

export async function runCli(
  argv: string[] = process.argv.slice(2),
): Promise<void> {
  const args = parseArgs(argv);

  if (!args.provider) {
    console.log(`
🪝 verihook CLI Simulator

Usage:
  npx verihook simulate <provider> [options]

Supported Providers:
  stripe, github, shopify, slack, twilio, svix, resend, clerk, meta, whatsapp, discord, twitter, x, paypal, lemonsqueezy, paddle, pagerduty, webflow, workos, linear, razorpay, square, zoom

Options:
  --url <url>          Target webhook server endpoint (default: http://localhost:3000/webhooks/<provider>)
  --secret <key>       Webhook signing secret
  --event <type>       Event type payload name
  --curl               Print cURL command instead of sending POST request
  --allow-remote       Allow sending simulation requests to non-local remote servers

Examples:
  npx verihook simulate stripe --url http://localhost:3000/webhooks/stripe
  npx verihook simulate github --event issues
  npx verihook simulate whatsapp --secret meta_app_secret_123
  npx verihook simulate lemonsqueezy --secret lemon_secret_777
`);
    return;
  }

  const provider = args.provider;
  const rawTargetUrl = args.url || `http://localhost:3000/webhooks/${provider}`;
  const eventType = args.event;

  const targetUrlObj = validateUrlForSsrf(rawTargetUrl, !!args.allowRemote);
  const targetUrl = targetUrlObj.toString();

  let headers: Record<string, string> = { "content-type": "application/json" };
  let rawBody = "";
  let secret = args.secret;

  switch (provider) {
    case "stripe": {
      secret = secret || "whsec_stripe_test_secret_123";
      const eventName = eventType || "payment_intent.succeeded";
      rawBody = JSON.stringify({
        id: `evt_${Date.now()}`,
        object: "event",
        type: eventName,
        data: {
          object: {
            id: "pi_3MtwBwLkdIwHu7ix",
            amount: 2000,
            currency: "usd",
            status: "succeeded",
          },
        },
      });
      const timestamp = Math.floor(Date.now() / 1000);
      const payloadToSign = `${timestamp}.${rawBody}`;
      const hmac = await computeHmacSha256(secret, payloadToSign);
      headers["stripe-signature"] = `t=${timestamp},v1=${bytesToHex(hmac)}`;
      break;
    }

    case "github": {
      secret = secret || "github_secret_123";
      const eventName = eventType || "issues";
      rawBody = JSON.stringify({
        action: "opened",
        issue: { number: 42, title: "Simulated issue via verihook CLI" },
        repository: { name: "verihook", owner: { login: "creatorpiyush" } },
      });
      const hmac = await computeHmacSha256(secret, rawBody);
      headers["x-hub-signature-256"] = `sha256=${bytesToHex(hmac)}`;
      headers["x-github-event"] = eventName;
      break;
    }

    case "meta":
    case "whatsapp":
    case "facebook":
    case "instagram": {
      secret = secret || "meta_app_secret_123";
      rawBody = JSON.stringify({
        object: "whatsapp_business_account",
        entry: [
          {
            id: "123456789",
            changes: [
              {
                value: {
                  messaging_product: "whatsapp",
                  messages: [
                    { from: "15551234567", text: { body: "Hello verihook!" } },
                  ],
                },
              },
            ],
          },
        ],
      });
      const hmac = await computeHmacSha256(secret, rawBody);
      headers["x-hub-signature-256"] = `sha256=${bytesToHex(hmac)}`;
      break;
    }

    case "twitter":
    case "x": {
      secret = secret || "twitter_consumer_secret_123";
      rawBody = JSON.stringify({
        for_user_id: "12345678",
        tweet_create_events: [
          {
            id_str: "999888777",
            text: "Testing verihook CLI simulation for Twitter/X",
          },
        ],
      });
      const hmac = await computeHmacSha256(secret, rawBody);
      headers["x-twitter-webhooks-signature"] = `sha256=${bytesToBase64(hmac)}`;
      break;
    }

    case "lemonsqueezy": {
      secret = secret || "lemon_secret_123";
      rawBody = JSON.stringify({
        meta: { event_name: eventType || "order_created" },
        data: { id: "100", attributes: { total: 2900, status: "paid" } },
      });
      const hmac = await computeHmacSha256(secret, rawBody);
      headers["x-signature"] = bytesToHex(hmac);
      break;
    }

    case "paddle": {
      secret = secret || "paddle_secret_123";
      const timestamp = Math.floor(Date.now() / 1000);
      rawBody = JSON.stringify({
        event_type: eventType || "transaction.completed",
        data: { id: "txn_100" },
      });
      const payloadToSign = `${timestamp}:${rawBody}`;
      const hmac = await computeHmacSha256(secret, payloadToSign);
      headers["paddle-signature"] = `ts=${timestamp};h=${bytesToHex(hmac)}`;
      break;
    }

    case "pagerduty": {
      secret = secret || "pagerduty_secret_123";
      rawBody = JSON.stringify({
        event: { event_type: eventType || "incident.triggered", id: "pd_100" },
      });
      const hmac = await computeHmacSha256(secret, rawBody);
      headers["x-pagerduty-signature"] = `v1=${bytesToHex(hmac)}`;
      break;
    }

    case "webflow": {
      secret = secret || "webflow_secret_123";
      const timestamp = Math.floor(Date.now() / 1000);
      rawBody = JSON.stringify({
        triggerType: eventType || "form_submission",
        site: "site_123",
      });
      headers["x-webflow-timestamp"] = String(timestamp);
      const payloadToSign = `${timestamp}:${rawBody}`;
      const hmac = await computeHmacSha256(secret, payloadToSign);
      headers["x-webflow-signature"] = `sha256=${bytesToHex(hmac)}`;
      break;
    }

    case "workos": {
      secret = secret || "workos_secret_123";
      const timestamp = Math.floor(Date.now() / 1000);
      rawBody = JSON.stringify({
        event: eventType || "user.created",
        data: { id: "user_100" },
      });
      const payloadToSign = `${timestamp}.${rawBody}`;
      const hmac = await computeHmacSha256(secret, payloadToSign);
      headers["workos-signature"] = `t=${timestamp},v1=${bytesToHex(hmac)}`;
      break;
    }

    case "svix":
    case "resend":
    case "clerk": {
      const rawSecret =
        secret && secret.startsWith("whsec_")
          ? secret.slice(6)
          : secret || "MfKQ9r8GKY2ly3ShZsKm7zpAKGJikF3g";
      const msgId = `msg_${Date.now()}`;
      const timestamp = Math.floor(Date.now() / 1000);
      rawBody = JSON.stringify({
        type: eventType || "user.created",
        data: { id: "usr_simulated_100" },
      });
      const payloadToSign = `${msgId}.${timestamp}.${rawBody}`;
      const hmac = await computeHmacSha256(
        base64ToBytes(rawSecret),
        payloadToSign,
      );
      headers["svix-id"] = msgId;
      headers["svix-timestamp"] = String(timestamp);
      headers["svix-signature"] = `v1,${bytesToBase64(hmac)}`;
      break;
    }

    case "slack": {
      secret = secret || "slack_signing_secret_123";
      const timestamp = Math.floor(Date.now() / 1000);
      rawBody = "token=gIOm5BIZJR0DZ3enR&team_id=T0001&command=%2Fverihook";
      headers["content-type"] = "application/x-www-form-urlencoded";
      headers["x-slack-request-timestamp"] = String(timestamp);
      const sigBase = `v0:${timestamp}:${rawBody}`;
      const hmac = await computeHmacSha256(secret, sigBase);
      headers["x-slack-signature"] = `v0=${bytesToHex(hmac)}`;
      break;
    }

    case "twilio": {
      secret = secret || "twilio_auth_token_123";
      rawBody = JSON.stringify({
        MessageSid: "SM12345",
        Body: "Simulated SMS",
      });
      const hashBytes = await computeSha256(rawBody);
      const hashHex = bytesToHex(hashBytes).toLowerCase();
      const delimiter = targetUrl.includes("?") ? "&" : "?";
      const dataToSign = `${targetUrl}${delimiter}bodySHA256=${encodeURIComponent(hashHex)}`;
      const hmac = await computeHmacSha1(secret, dataToSign);
      headers["x-twilio-signature"] = bytesToBase64(hmac);
      break;
    }

    default: {
      secret = secret || "secret_123";
      rawBody = JSON.stringify({
        event: eventType || "simulated_event",
        timestamp: Date.now(),
      });
      const hmac = await computeHmacSha256(secret, rawBody);
      headers["x-signature-256"] = bytesToHex(hmac);
      break;
    }
  }

  if (args.printCurl) {
    const headerFlags = Object.entries(headers)
      .map(([k, v]) => `-H "${k}: ${v}"`)
      .join(" ");
    console.log(`curl -X POST "${targetUrl}" ${headerFlags} -d '${rawBody}'`);
    return;
  }

  console.log(`\n📡 Simulating signed ${provider.toUpperCase()} webhook...`);
  console.log(`🎯 URL: ${targetUrl}`);
  console.log(`🔑 Headers:`, redactHeaders(headers));
  console.log(`📦 Body:`, rawBody);

  try {
    const res = await fetch(targetUrl, {
      method: "POST",
      headers,
      body: rawBody,
    });

    const statusText =
      res.status >= 200 && res.status < 300 ? "✅ SUCCESS" : "❌ FAILED";
    console.log(`\n${statusText} [HTTP ${res.status}]`);

    const responseText = await res.text();
    try {
      console.log("Response:", JSON.parse(responseText));
    } catch {
      console.log("Response:", responseText);
    }
  } catch (err: unknown) {
    const errorMsg = err instanceof Error ? err.message : String(err);
    console.error(`\n❌ Could not connect to ${targetUrl}:`, errorMsg);
  }
}

function isDirectRun(): boolean {
  if (!process.argv[1]) return false;
  try {
    const mainPath = fs.realpathSync(process.argv[1]);

    if (typeof require !== "undefined" && require.main) {
      return require.main.filename === mainPath;
    }

    let metaUrl: string | undefined;
    try {
      metaUrl = new Function("return import.meta.url")();
    } catch {
      metaUrl = undefined;
    }

    if (metaUrl) {
      return fs.realpathSync(fileURLToPath(metaUrl)) === mainPath;
    }

    const scriptPath = process.argv[1];
    return (
      scriptPath.endsWith("/cli/index.js") ||
      scriptPath.endsWith("/cli/index.ts") ||
      scriptPath.endsWith("/cli.js") ||
      scriptPath.endsWith("/cli.mjs") ||
      scriptPath.endsWith("/verihook") ||
      scriptPath.endsWith("/bin/verihook")
    );
  } catch {
    return false;
  }
}

if (isDirectRun()) {
  process.on("unhandledRejection", (reason) => {
    console.error("[verihook] Unhandled Promise Rejection:", reason);
  });

  process.on("SIGINT", () => {
    console.log("\n👋 Simulation cancelled by user (SIGINT). Exiting cleanly.");
    process.exit(0);
  });

  process.on("SIGTERM", () => {
    console.log("\n👋 Received SIGTERM. Exiting cleanly.");
    process.exit(0);
  });

  runCli().catch((err) => {
    console.error("[verihook] Fatal CLI Error:", err);
    process.exit(1);
  });
}
