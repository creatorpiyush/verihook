#!/usr/bin/env node
import type { Server } from "http";
import fs from "node:fs";
import * as http from "node:http";
import process from "node:process";
import { ProviderName } from "../core/types.js";
import { verifyWebhook } from "../core/verifier.js";
import { ParsedCliArgs, validateCliArgs } from "../schemas/index.js";
import {
  SIGNABLE_PROVIDERS,
  SignWebhookOptions,
  signWebhook,
} from "../testing/sign.js";

// Injected from package.json at build time (tsup/vitest `define`).
declare const __VERIHOOK_VERSION__: string | undefined;
const CLI_VERSION =
  typeof __VERIHOOK_VERSION__ === "string" ? __VERIHOOK_VERSION__ : "dev";

// Wraps a value in single quotes for POSIX shells, escaping embedded quotes.
function shellQuote(value: string): string {
  return `'${value.replace(/'/g, "'\\''")}'`;
}

// Value after the first "=" so secrets with base64 padding and URLs with queries survive.
function flagValue(arg: string): string {
  return arg.slice(arg.indexOf("=") + 1);
}

function parseArgs(args: string[]): ParsedCliArgs {
  const rawResult: Record<string, unknown> = {};
  let commandDetected = false;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (
      (arg === "simulate" || arg === "listen") &&
      i + 1 < args.length &&
      !args[i + 1].startsWith("-")
    ) {
      rawResult.command = arg;
      rawResult.provider = args[i + 1].toLowerCase();
      commandDetected = true;
      i++;
    } else if (arg.startsWith("--forward-to=")) {
      rawResult.forwardTo = flagValue(arg);
    } else if (arg === "--forward-to" && i + 1 < args.length) {
      rawResult.forwardTo = args[i + 1];
      i++;
    } else if (arg.startsWith("--port=")) {
      rawResult.port = flagValue(arg);
    } else if ((arg === "--port" || arg === "-p") && i + 1 < args.length) {
      rawResult.port = args[i + 1];
      i++;
    } else if (arg.startsWith("--path=")) {
      rawResult.path = flagValue(arg);
    } else if (arg === "--path" && i + 1 < args.length) {
      rawResult.path = args[i + 1];
      i++;
    } else if (arg.startsWith("--url=")) {
      rawResult.url = flagValue(arg);
    } else if (arg === "--url" && i + 1 < args.length) {
      rawResult.url = args[i + 1];
      i++;
    } else if (arg.startsWith("--secret=")) {
      rawResult.secret = flagValue(arg);
    } else if (arg === "--secret" && i + 1 < args.length) {
      rawResult.secret = args[i + 1];
      i++;
    } else if (arg.startsWith("--event=")) {
      rawResult.event = flagValue(arg);
    } else if (arg === "--event" && i + 1 < args.length) {
      rawResult.event = args[i + 1];
      i++;
    } else if (arg === "--curl") {
      rawResult.printCurl = true;
    } else if (arg === "--allow-remote") {
      rawResult.allowRemote = true;
    } else if (
      !commandDetected &&
      !arg.startsWith("-") &&
      !rawResult.provider
    ) {
      rawResult.command = "simulate";
      rawResult.provider = arg.toLowerCase();
    }
  }

  if (!rawResult.command && rawResult.provider) {
    rawResult.command = "simulate";
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

  if (
    cleanHost === "localhost" ||
    cleanHost === "127.0.0.1" ||
    cleanHost === "0.0.0.0" ||
    cleanHost === "0" ||
    cleanHost === "::1" ||
    cleanHost === "0177.0.0.1" ||
    cleanHost === "0x7f000001" ||
    cleanHost === "2130706433"
  ) {
    return true;
  }

  const ipMatch = cleanHost.match(
    /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/,
  );

  if (!ipMatch) {
    return false;
  }

  const [_, o1, o2] = ipMatch.map(Number);

  // 0.0.0.0/8
  if (o1 === 0) return true;
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

/**
 * Denylist-based SSRF host origin validation.
 *
 * Provides best-effort defense-in-depth hardening against known cloud metadata
 * endpoints (e.g., 169.254.169.254) and common encoding bypasses.
 * Note: Denylist-based validation is inherently incomplete and is not a substitute
 * for network-level isolation (such as VPC security groups, firewalls, or egress proxies).
 */
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

export async function runListenServer(
  args: ParsedCliArgs,
  onListening?: (server: Server) => void,
): Promise<Server> {
  const provider = (args.provider || "generic") as ProviderName;
  const port = args.port || 8080;
  const rawTargetUrl =
    args.forwardTo || args.url || `http://localhost:3000/webhooks/${provider}`;

  const targetUrlObj = validateUrlForSsrf(rawTargetUrl, !!args.allowRemote);
  const targetUrl = targetUrlObj.toString();
  const secret = args.secret;

  const server = http.createServer(async (req, res) => {
    const startTime = performance.now();
    const reqMethod = req.method || "POST";
    const reqUrl = req.url || "/";
    const timestampStr = new Date().toISOString();

    const bodyChunks: Buffer[] = [];
    for await (const chunk of req) {
      bodyChunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
    }
    const rawBody = Buffer.concat(bodyChunks).toString("utf-8");

    const headers: Record<string, string> = {};
    for (const [key, value] of Object.entries(req.headers)) {
      if (typeof value === "string") {
        headers[key.toLowerCase()] = value;
      } else if (Array.isArray(value)) {
        headers[key.toLowerCase()] = value.join(", ");
      }
    }

    console.log(
      `\n📥 [${timestampStr}] Incoming ${reqMethod} ${reqUrl} (${provider.toUpperCase()})`,
    );

    let verificationDetail = "";

    if (secret) {
      try {
        const verifyStart = performance.now();
        const result = await verifyWebhook(
          provider,
          { headers, body: rawBody, url: targetUrl },
          secret,
        );
        const durationMs = Math.round(performance.now() - verifyStart);
        if (result.valid) {
          verificationDetail = `✅ SIGNATURE MATCH (${durationMs}ms)`;
        } else {
          verificationDetail = `❌ INVALID SIGNATURE (${result.code}: ${result.reason})`;
        }
      } catch (err: unknown) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        verificationDetail = `❌ VERIFICATION ERROR (${errorMsg})`;
      }
    } else {
      verificationDetail = `ℹ️ UNVERIFIED (No --secret provided)`;
    }

    console.log(`  🛡️  Verification: ${verificationDetail}`);
    console.log(`  📋 Headers:`, redactHeaders(headers));
    if (rawBody) {
      const bodySnippet =
        rawBody.length > 300
          ? rawBody.slice(0, 300) + "... [truncated]"
          : rawBody;
      console.log(`  📦 Body:`, bodySnippet);
    }

    try {
      const forwardHeaders = { ...headers };
      delete forwardHeaders["host"];
      delete forwardHeaders["content-length"];

      const targetRes = await fetch(targetUrl, {
        method: reqMethod,
        headers: forwardHeaders,
        body: reqMethod !== "GET" && reqMethod !== "HEAD" ? rawBody : undefined,
      });

      const durationMs = Math.round(performance.now() - startTime);
      const statusIcon = targetRes.ok ? "✅ SUCCESS" : "⚠️ RESPONDED";
      console.log(
        `  ➡️  Forwarded to ${targetUrl} -> ${statusIcon} [HTTP ${targetRes.status}] (${durationMs}ms)`,
      );

      const targetResponseBody = await targetRes.text();
      const resHeaders: Record<string, string> = {};
      targetRes.headers.forEach((val, key) => {
        const lowerKey = key.toLowerCase();
        if (
          lowerKey !== "content-encoding" &&
          lowerKey !== "content-length" &&
          lowerKey !== "transfer-encoding"
        ) {
          resHeaders[key] = val;
        }
      });

      res.writeHead(targetRes.status, resHeaders);
      res.end(targetResponseBody);
    } catch (err: unknown) {
      const durationMs = Math.round(performance.now() - startTime);
      const errorMsg = err instanceof Error ? err.message : String(err);
      console.error(
        `  ❌ Forwarding Failed to ${targetUrl} (${durationMs}ms): ${errorMsg}`,
      );

      res.writeHead(502, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          error: "Bad Gateway",
          message: `Forwarding failed: ${errorMsg}`,
        }),
      );
    }
  });

  return new Promise((resolve, reject) => {
    server.listen(port, () => {
      console.log(`
🪝 verihook Live Local Relay Proxy (v${CLI_VERSION})

📡 Provider:     ${provider.toUpperCase()}
👂 Listening on: http://localhost:${port}
➡️  Forwarding to: ${targetUrl}
🔐 Verification: ${secret ? "ENABLED (Secret configured)" : "DISABLED (Pass --secret to verify incoming webhooks)"}

Press Ctrl+C to stop listening.
`);
      if (onListening) onListening(server);
      resolve(server);
    });

    server.on("error", (err) => {
      reject(err);
    });
  });
}

// Default secrets and example payloads used by `simulate`.
const KEY_PAIR_PROVIDERS = new Set(["discord", "sendgrid"]);

function simulationSample(
  provider: string,
  eventType: string | undefined,
): Pick<SignWebhookOptions, "secret" | "payload" | "form" | "event"> {
  const now = Date.now();
  switch (provider) {
    case "stripe":
      return {
        secret: "whsec_stripe_test_secret_123",
        payload: {
          id: `evt_${now}`,
          object: "event",
          type: eventType || "payment_intent.succeeded",
          data: {
            object: {
              id: "pi_3MtwBwLkdIwHu7ix",
              amount: 2000,
              currency: "usd",
              status: "succeeded",
            },
          },
        },
      };
    case "github":
      return {
        secret: "github_secret_123",
        event: eventType || "issues",
        payload: {
          action: "opened",
          issue: { number: 42, title: "Simulated issue via verihook CLI" },
          repository: { name: "verihook", owner: { login: "creatorpiyush" } },
        },
      };
    case "shopify":
      return {
        secret: "shopify_secret_123",
        event: eventType || "orders/create",
        payload: { id: now },
      };
    case "meta":
    case "whatsapp":
    case "facebook":
    case "instagram":
      return {
        secret: "meta_app_secret_123",
        payload: {
          object: "whatsapp_business_account",
          entry: [
            {
              id: "123456789",
              changes: [
                {
                  value: {
                    messaging_product: "whatsapp",
                    messages: [
                      {
                        from: "15551234567",
                        text: { body: "Hello verihook!" },
                      },
                    ],
                  },
                },
              ],
            },
          ],
        },
      };
    case "twitter":
    case "x":
      return {
        secret: "twitter_consumer_secret_123",
        payload: {
          for_user_id: "12345678",
          tweet_create_events: [
            {
              id_str: "999888777",
              text: "Testing verihook CLI simulation for Twitter/X",
            },
          ],
        },
      };
    case "lemonsqueezy":
      return {
        secret: "lemon_secret_123",
        payload: {
          meta: { event_name: eventType || "order_created" },
          data: { id: "100", attributes: { total: 2900, status: "paid" } },
        },
      };
    case "paddle":
      return {
        secret: "paddle_secret_123",
        payload: {
          event_type: eventType || "transaction.completed",
          data: { id: "txn_100" },
        },
      };
    case "pagerduty":
      return {
        secret: "pagerduty_secret_123",
        payload: {
          event: {
            event_type: eventType || "incident.triggered",
            id: "pd_100",
          },
        },
      };
    case "webflow":
      return {
        secret: "webflow_secret_123",
        payload: {
          triggerType: eventType || "form_submission",
          site: "site_123",
        },
      };
    case "workos":
      return {
        secret: "workos_secret_123",
        payload: {
          event: eventType || "user.created",
          data: { id: "user_100" },
        },
      };
    case "svix":
    case "resend":
    case "clerk":
      return {
        secret: "dGVzdF9zZWNyZXRfa2V5X2Zvcl9zdml4XzEyMw==",
        payload: {
          type: eventType || "user.created",
          data: { id: "usr_simulated_100" },
        },
      };
    case "slack":
      return {
        secret: "slack_signing_secret_123",
        form: {
          token: "slack_token_test_123",
          team_id: "T0001",
          command: "/verihook",
        },
      };
    case "twilio":
      return {
        secret: "twilio_auth_token_123",
        payload: { MessageSid: "SM12345", Body: "Simulated SMS" },
      };
    case "square":
      return {
        secret: "square_signature_key_123",
        payload: {
          type: eventType || "payment.created",
          event_id: `sq_${now}`,
        },
      };
    case "zoom":
      return {
        secret: "zoom_secret_token_123",
        payload: {
          event: eventType || "meeting.started",
          payload: { object: { id: "123456789" } },
        },
      };
    case "linear":
      return {
        secret: "linear_secret_123",
        payload: {
          action: "create",
          type: eventType || "Issue",
          data: { id: "lin_100" },
        },
      };
    case "razorpay":
      return {
        secret: "razorpay_secret_123",
        payload: {
          event: eventType || "payment.captured",
          payload: { payment: { entity: { id: "pay_100" } } },
        },
      };
    case "cashfree":
      return {
        secret: "cashfree_client_secret_123",
        payload: {
          type: eventType || "PAYMENT_SUCCESS_WEBHOOK",
          event_time: new Date(now).toISOString(),
          data: {
            order: { order_id: `order_${now}`, order_amount: 100 },
            payment: { cf_payment_id: now, payment_status: "SUCCESS" },
          },
        },
      };
    case "phonepe":
      return {
        secret: "webhook_user:webhook_password",
        payload: {
          event: eventType || "checkout.order.completed",
          payload: { orderId: `OMO${now}`, state: "COMPLETED", amount: 10000 },
        },
      };
    case "mollie":
      return {
        secret: "mollie_signing_secret_123",
        payload: {
          resource: "event",
          id: `event_${now}`,
          type: eventType || "payment-link.paid",
          entityId: "pl_simulated",
          createdAt: new Date(now).toISOString(),
        },
      };
    case "adyen":
      return {
        // Adyen HMAC keys are hex; this placeholder is not a real key.
        secret:
          "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        payload: {
          live: "false",
          notificationItems: [
            {
              NotificationRequestItem: {
                eventCode: eventType || "AUTHORISATION",
                success: "true",
                pspReference: String(now),
                merchantAccountCode: "TestMerchant",
                merchantReference: `order_${now}`,
                amount: { value: 1000, currency: "EUR" },
                eventDate: new Date(now).toISOString(),
              },
            },
          ],
        },
      };
    case "checkout":
      return {
        secret: "checkout_signature_key_123",
        payload: {
          id: `evt_${now}`,
          type: eventType || "payment_approved",
          created_on: new Date(now).toISOString(),
          data: { id: "pay_simulated", amount: 1000, currency: "EUR" },
        },
      };
    case "authorizenet":
      return {
        secret: "authorizenet_signature_key_123",
        payload: {
          notificationId: `notif_${now}`,
          eventType: eventType || "net.authorize.payment.authcapture.created",
          eventDate: new Date(now).toISOString(),
          webhookId: "webhook_simulated",
          payload: { responseCode: 1, authAmount: 10, id: String(now) },
        },
      };
    case "recurly":
      return {
        secret: "recurly_webhook_secret_123",
        payload: {
          id: `notif_${now}`,
          object_type: "subscription",
          site_id: "site_simulated",
          event_type: eventType || "created",
          event_time: new Date(now).toISOString(),
          account_code: "account_simulated",
        },
      };
    case "gitlab":
      return {
        secret: "gitlab_secret_token_123",
        event: "Push Hook",
        payload: {
          object_kind: eventType || "push",
          ref: "refs/heads/main",
          user_username: "verihook",
          project: { id: 1, path_with_namespace: "creatorpiyush/verihook" },
        },
      };
    case "bitbucket":
      return {
        secret: "bitbucket_secret_123",
        event: eventType || "repo:push",
        payload: {
          actor: { display_name: "verihook" },
          repository: { full_name: "creatorpiyush/verihook" },
          push: { changes: [] },
        },
      };
    case "vercel":
      return {
        secret: "vercel_webhook_secret_123",
        payload: {
          id: `evt_${now}`,
          type: eventType || "deployment.succeeded",
          createdAt: now,
          payload: {
            deployment: { id: "dpl_simulated", url: "verihook.vercel.app" },
          },
        },
      };
    case "sentry":
      return {
        secret: "sentry_client_secret_123",
        event: "issue",
        payload: {
          action: eventType || "created",
          installation: { uuid: "inst_simulated" },
          data: { issue: { id: String(now), title: "Simulated issue" } },
          actor: { type: "application", id: "sentry", name: "Sentry" },
        },
      };
    case "twitch":
      return {
        secret: "twitch_eventsub_secret_123",
        event: eventType || "channel.follow",
        payload: {
          subscription: {
            id: `sub_${now}`,
            type: eventType || "channel.follow",
            version: "2",
            status: "enabled",
            condition: { broadcaster_user_id: "1337" },
          },
          event: {
            user_id: "1234",
            user_login: "verihook",
            broadcaster_user_id: "1337",
          },
        },
      };
    case "telegram":
      return {
        secret: "telegram_secret_token_123",
        payload: {
          update_id: now % 1_000_000_000,
          message: {
            message_id: 1,
            chat: { id: 42, type: "private" },
            text: "Hello verihook!",
          },
        },
      };
    case "postmark":
      return {
        secret: "postmark_user:postmark_pass",
        payload: {
          RecordType: eventType || "Delivery",
          MessageID: `msg_${now}`,
          Recipient: "user@example.com",
          MessageStream: "outbound",
        },
      };
    case "sendgrid":
      return {
        payload: [
          {
            email: "user@example.com",
            timestamp: Math.floor(now / 1000),
            event: eventType || "delivered",
            sg_event_id: `sg_${now}`,
            sg_message_id: "msg_simulated",
          },
        ],
      };
    case "mailgun":
      return {
        secret: "mailgun_signing_key_123",
        payload: {
          "event-data": {
            event: eventType || "delivered",
            id: `evt_${now}`,
            timestamp: now / 1000,
            recipient: "user@example.com",
          },
        },
      };
    case "hubspot":
      return {
        secret: "hubspot_client_secret_123",
        payload: [
          {
            eventId: now,
            subscriptionId: 1,
            portalId: 62515,
            appId: 54321,
            occurredAt: now,
            subscriptionType: eventType || "contact.creation",
            attemptNumber: 0,
            objectId: 123,
          },
        ],
      };
    case "intercom":
      return {
        secret: "intercom_client_secret_123",
        payload: {
          type: "notification_event",
          id: `notif_${now}`,
          topic: eventType || "conversation.user.created",
          app_id: "app_simulated",
          created_at: Math.floor(now / 1000),
          data: {
            type: "notification_event_data",
            item: { type: "conversation", id: "1" },
          },
        },
      };
    case "calendly":
      return {
        secret: "calendly_signing_key_123",
        payload: {
          event: eventType || "invitee.created",
          created_at: new Date(now).toISOString(),
          created_by: "https://api.calendly.com/users/simulated",
          payload: { email: "invitee@example.com", name: "Simulated Invitee" },
        },
      };
    case "typeform":
      return {
        secret: "typeform_secret_123",
        payload: {
          event_id: `evt_${now}`,
          event_type: eventType || "form_response",
          form_response: {
            form_id: "simulated",
            token: `tok_${now}`,
            submitted_at: new Date(now).toISOString(),
            answers: [],
          },
        },
      };
    case "discord":
      return { payload: { type: 1, id: `interaction_${now}` } };
    default:
      return {
        secret: "secret_123",
        payload: { event: eventType || "simulated_event", timestamp: now },
      };
  }
}

export async function runCli(
  argv: string[] = process.argv.slice(2),
): Promise<void> {
  const args = parseArgs(argv);

  if (!args.provider) {
    console.log(`
🪝 verihook CLI Toolchain (v${CLI_VERSION})

Usage:
  npx verihook simulate <provider> [options]
  npx verihook listen <provider> [options]

Commands:
  simulate <provider>  Generate and send a signed webhook simulation
  listen <provider>    Run a live local relay proxy intercepting & forwarding webhooks

Supported Providers:
  stripe, github, shopify, slack, twilio, svix, resend, clerk, meta, whatsapp, discord, twitter, x, paypal, lemonsqueezy, paddle, pagerduty, webflow, workos, linear, razorpay, square, zoom,
  cashfree, phonepe, mollie, adyen, checkout, authorizenet, recurly,
  gitlab, bitbucket, vercel, sentry, twitch, telegram, postmark, sendgrid, mailgun,
  hubspot, intercom, calendly, typeform

Options:
  --forward-to <url>   Target webhook server endpoint to forward webhooks to (listen mode)
  -p, --port <port>    Local port for relay proxy server (default: 8080)
  --url <url>          Target webhook server endpoint (simulate mode)
  --secret <key>       Webhook signing secret
  --event <type>       Event type payload name
  --curl               Print cURL command instead of sending POST request (simulate mode)
  --allow-remote       Allow sending simulation or forwarding requests to non-local remote servers

Examples:
  npx verihook simulate stripe --url http://localhost:3000/webhooks/stripe
  npx verihook listen stripe --forward-to http://localhost:3000/webhooks/stripe --secret whsec_123
  npx verihook listen github -p 8080 --forward-to http://localhost:4000/api/github
`);
    return;
  }

  if (args.command === "listen") {
    await runListenServer(args);
    return;
  }

  const provider = args.provider;
  const rawTargetUrl = args.url || `http://localhost:3000/webhooks/${provider}`;
  const eventType = args.event;

  const targetUrlObj = validateUrlForSsrf(rawTargetUrl, !!args.allowRemote);
  const targetUrl = targetUrlObj.toString();

  if (provider === "paypal") {
    console.error(
      "❌ PayPal webhooks are signed with PayPal's private RSA key and cannot be simulated locally. Use the PayPal Developer Dashboard webhook simulator instead.",
    );
    process.exitCode = 1;
    return;
  }

  if (provider === "discord" && args.secret) {
    console.warn(
      "⚠️ Ignoring --secret for discord: simulation signs with a generated Ed25519 key pair.",
    );
  }

  const sample = simulationSample(provider, eventType);
  // Unknown names fall back to the generic verifier's defaults (x-signature, hex HMAC-SHA256).
  const signProvider = SIGNABLE_PROVIDERS.has(provider) ? provider : "generic";
  const signed = await signWebhook(signProvider, {
    ...sample,
    // Discord and SendGrid sign with a private key; a throwaway pair is generated.
    secret: KEY_PAIR_PROVIDERS.has(provider)
      ? undefined
      : args.secret || sample.secret,
    url: targetUrl,
  });
  const { headers, body: rawBody } = signed;
  // Twilio JSON webhooks carry the body hash in the signed URL.
  const sendUrl = signed.url;

  if (KEY_PAIR_PROVIDERS.has(provider)) {
    const label = provider === "discord" ? "Discord" : "SendGrid";
    console.log(`🔑 ${label} public key for verification: ${signed.secret}`);
  }

  if (args.printCurl) {
    const headerFlags = Object.entries(headers)
      .map(([k, v]) => `-H ${shellQuote(`${k}: ${v}`)}`)
      .join(" ");
    console.log(
      `curl -X POST ${shellQuote(sendUrl)} ${headerFlags} -d ${shellQuote(rawBody)}`,
    );
    return;
  }

  console.log(`\n📡 Simulating signed ${provider.toUpperCase()} webhook...`);
  console.log(`🎯 URL: ${sendUrl}`);
  console.log(`🔑 Headers:`, redactHeaders(headers));
  console.log(`📦 Body:`, rawBody);

  try {
    const res = await fetch(sendUrl, {
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
    console.error(`\n❌ Could not connect to ${sendUrl}:`, errorMsg);
  }
}

function isDirectRun(): boolean {
  if (!process.argv[1]) return false;
  try {
    const mainPath = fs.realpathSync(process.argv[1]);

    if (typeof require !== "undefined" && require.main) {
      return require.main.filename === mainPath;
    }

    const scriptPath = process.argv[1];
    return (
      scriptPath.endsWith("/cli/index.js") ||
      scriptPath.endsWith("/cli/index.ts") ||
      scriptPath.endsWith("/cli.js") ||
      scriptPath.endsWith("/cli.mjs") ||
      scriptPath.endsWith("/verihook") ||
      scriptPath.endsWith("/bin/verihook") ||
      mainPath.endsWith("/cli/index.js") ||
      mainPath.endsWith("/cli.js") ||
      mainPath.endsWith("/cli.mjs")
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
