#!/usr/bin/env node
import { computeHmacSha1, computeHmacSha256, computeSha256 } from '../core/crypto.js';
import { base64ToBytes, bytesToBase64, bytesToHex } from '../utils/encoding.js';

interface CliArgs {
  provider?: string;
  url?: string;
  secret?: string;
  event?: string;
  printCurl?: boolean;
}

function parseArgs(args: string[]): CliArgs {
  const result: CliArgs = {};
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === 'simulate' && i + 1 < args.length && !args[i + 1].startsWith('-')) {
      result.provider = args[i + 1].toLowerCase();
      i++;
    } else if (arg.startsWith('--url=')) {
      result.url = arg.split('=')[1];
    } else if (arg === '--url' && i + 1 < args.length) {
      result.url = args[i + 1];
      i++;
    } else if (arg.startsWith('--secret=')) {
      result.secret = arg.split('=')[1];
    } else if (arg === '--secret' && i + 1 < args.length) {
      result.secret = args[i + 1];
      i++;
    } else if (arg.startsWith('--event=')) {
      result.event = arg.split('=')[1];
    } else if (arg === '--event' && i + 1 < args.length) {
      result.event = args[i + 1];
      i++;
    } else if (arg === '--curl') {
      result.printCurl = true;
    }
  }
  return result;
}

export async function runCli(argv: string[] = process.argv.slice(2)): Promise<void> {
  const args = parseArgs(argv);

  if (!args.provider) {
    console.log(`
🪝 verihook CLI Simulator

Usage:
  npx verihook simulate <provider> [options]

Supported Providers:
  stripe, github, shopify, slack, twilio, svix, resend, clerk, meta, whatsapp, discord, twitter, x, paypal, lemonsqueezy, paddle, pagerduty, webflow, workos, linear, razorpay, square, zoom

Options:
  --url <url>      Target webhook server endpoint (default: http://localhost:3000/webhooks/<provider>)
  --secret <key>   Webhook signing secret
  --event <type>   Event type payload name
  --curl           Print cURL command instead of sending POST request

Examples:
  npx verihook simulate stripe --url http://localhost:3000/webhooks/stripe
  npx verihook simulate github --event issues
  npx verihook simulate whatsapp --secret meta_app_secret_123
  npx verihook simulate lemonsqueezy --secret lemon_secret_777
`);
    return;
  }

  const provider = args.provider;
  const targetUrl = args.url || `http://localhost:3000/webhooks/${provider}`;
  const eventType = args.event;

  let headers: Record<string, string> = { 'content-type': 'application/json' };
  let rawBody = '';
  let secret = args.secret;

  switch (provider) {
    case 'stripe': {
      secret = secret || 'whsec_stripe_test_secret_123';
      const eventName = eventType || 'payment_intent.succeeded';
      rawBody = JSON.stringify({
        id: `evt_${Date.now()}`,
        object: 'event',
        type: eventName,
        data: { object: { id: 'pi_3MtwBwLkdIwHu7ix', amount: 2000, currency: 'usd', status: 'succeeded' } },
      });
      const timestamp = Math.floor(Date.now() / 1000);
      const payloadToSign = `${timestamp}.${rawBody}`;
      const hmac = await computeHmacSha256(secret, payloadToSign);
      headers['stripe-signature'] = `t=${timestamp},v1=${bytesToHex(hmac)}`;
      break;
    }

    case 'github': {
      secret = secret || 'github_secret_123';
      const eventName = eventType || 'issues';
      rawBody = JSON.stringify({
        action: 'opened',
        issue: { number: 42, title: 'Simulated issue via verihook CLI' },
        repository: { name: 'verihook', owner: { login: 'creatorpiyush' } },
      });
      const hmac = await computeHmacSha256(secret, rawBody);
      headers['x-hub-signature-256'] = `sha256=${bytesToHex(hmac)}`;
      headers['x-github-event'] = eventName;
      break;
    }

    case 'meta':
    case 'whatsapp':
    case 'facebook':
    case 'instagram': {
      secret = secret || 'meta_app_secret_123';
      rawBody = JSON.stringify({
        object: 'whatsapp_business_account',
        entry: [{ id: '123456789', changes: [{ value: { messaging_product: 'whatsapp', messages: [{ from: '15551234567', text: { body: 'Hello verihook!' } }] } }] }],
      });
      const hmac = await computeHmacSha256(secret, rawBody);
      headers['x-hub-signature-256'] = `sha256=${bytesToHex(hmac)}`;
      break;
    }

    case 'twitter':
    case 'x': {
      secret = secret || 'twitter_consumer_secret_123';
      rawBody = JSON.stringify({
        for_user_id: '12345678',
        tweet_create_events: [{ id_str: '999888777', text: 'Testing verihook CLI simulation for Twitter/X' }],
      });
      const hmac = await computeHmacSha256(secret, rawBody);
      headers['x-twitter-webhooks-signature'] = `sha256=${bytesToBase64(hmac)}`;
      break;
    }

    case 'lemonsqueezy': {
      secret = secret || 'lemon_secret_123';
      rawBody = JSON.stringify({
        meta: { event_name: eventType || 'order_created' },
        data: { id: '100', attributes: { total: 2900, status: 'paid' } },
      });
      const hmac = await computeHmacSha256(secret, rawBody);
      headers['x-signature'] = bytesToHex(hmac);
      break;
    }

    case 'paddle': {
      secret = secret || 'paddle_secret_123';
      const timestamp = Math.floor(Date.now() / 1000);
      rawBody = JSON.stringify({ event_type: eventType || 'transaction.completed', data: { id: 'txn_100' } });
      const payloadToSign = `${timestamp}:${rawBody}`;
      const hmac = await computeHmacSha256(secret, payloadToSign);
      headers['paddle-signature'] = `ts=${timestamp};h=${bytesToHex(hmac)}`;
      break;
    }

    case 'pagerduty': {
      secret = secret || 'pagerduty_secret_123';
      rawBody = JSON.stringify({ event: { event_type: eventType || 'incident.triggered', id: 'pd_100' } });
      const hmac = await computeHmacSha256(secret, rawBody);
      headers['x-pagerduty-signature'] = `v1=${bytesToHex(hmac)}`;
      break;
    }

    case 'webflow': {
      secret = secret || 'webflow_secret_123';
      const timestamp = Math.floor(Date.now() / 1000);
      rawBody = JSON.stringify({ triggerType: eventType || 'form_submission', site: 'site_123' });
      headers['x-webflow-timestamp'] = String(timestamp);
      const payloadToSign = `${timestamp}:${rawBody}`;
      const hmac = await computeHmacSha256(secret, payloadToSign);
      headers['x-webflow-signature'] = `sha256=${bytesToHex(hmac)}`;
      break;
    }

    case 'workos': {
      secret = secret || 'workos_secret_123';
      const timestamp = Math.floor(Date.now() / 1000);
      rawBody = JSON.stringify({ event: eventType || 'user.created', data: { id: 'user_100' } });
      const payloadToSign = `${timestamp}.${rawBody}`;
      const hmac = await computeHmacSha256(secret, payloadToSign);
      headers['workos-signature'] = `t=${timestamp},v1=${bytesToHex(hmac)}`;
      break;
    }

    case 'svix':
    case 'resend':
    case 'clerk': {
      const rawSecret = secret && secret.startsWith('whsec_') ? secret.slice(6) : secret || 'MfKQ9r8GKY2ly3ShZsKm7zpAKGJikF3g';
      const msgId = `msg_${Date.now()}`;
      const timestamp = Math.floor(Date.now() / 1000);
      rawBody = JSON.stringify({ type: eventType || 'user.created', data: { id: 'usr_simulated_100' } });
      const payloadToSign = `${msgId}.${timestamp}.${rawBody}`;
      const hmac = await computeHmacSha256(base64ToBytes(rawSecret), payloadToSign);
      headers['svix-id'] = msgId;
      headers['svix-timestamp'] = String(timestamp);
      headers['svix-signature'] = `v1,${bytesToBase64(hmac)}`;
      break;
    }

    case 'slack': {
      secret = secret || 'slack_signing_secret_123';
      const timestamp = Math.floor(Date.now() / 1000);
      rawBody = 'token=gIOm5BIZJR0DZ3enR&team_id=T0001&command=%2Fverihook';
      headers['content-type'] = 'application/x-www-form-urlencoded';
      headers['x-slack-request-timestamp'] = String(timestamp);
      const sigBase = `v0:${timestamp}:${rawBody}`;
      const hmac = await computeHmacSha256(secret, sigBase);
      headers['x-slack-signature'] = `v0=${bytesToHex(hmac)}`;
      break;
    }

    case 'twilio': {
      secret = secret || 'twilio_auth_token_123';
      rawBody = JSON.stringify({ MessageSid: 'SM12345', Body: 'Simulated SMS' });
      const hashBytes = await computeSha256(rawBody);
      const hashHex = bytesToHex(hashBytes).toLowerCase();
      const dataToSign = `${targetUrl}?bodySHA256=${encodeURIComponent(hashHex)}`;
      const hmac = await computeHmacSha1(secret, dataToSign);
      headers['x-twilio-signature'] = bytesToBase64(hmac);
      break;
    }

    default: {
      secret = secret || 'secret_123';
      rawBody = JSON.stringify({ event: eventType || 'simulated_event', timestamp: Date.now() });
      const hmac = await computeHmacSha256(secret, rawBody);
      headers['x-signature-256'] = bytesToHex(hmac);
      break;
    }
  }

  if (args.printCurl) {
    const headerFlags = Object.entries(headers)
      .map(([k, v]) => `-H "${k}: ${v}"`)
      .join(' ');
    console.log(`curl -X POST "${targetUrl}" ${headerFlags} -d '${rawBody}'`);
    return;
  }

  console.log(`\n📡 Simulating signed ${provider.toUpperCase()} webhook...`);
  console.log(`🎯 URL: ${targetUrl}`);
  console.log(`🔑 Headers:`, headers);
  console.log(`📦 Body:`, rawBody);

  try {
    const res = await fetch(targetUrl, {
      method: 'POST',
      headers,
      body: rawBody,
    });

    const statusText = res.status >= 200 && res.status < 300 ? '✅ SUCCESS' : '❌ FAILED';
    console.log(`\n${statusText} [HTTP ${res.status}]`);

    const responseText = await res.text();
    try {
      console.log('Response:', JSON.parse(responseText));
    } catch {
      console.log('Response:', responseText);
    }
  } catch (err: any) {
    console.error(`\n❌ Could not connect to ${targetUrl}:`, err.message);
  }
}

runCli();
