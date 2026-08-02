import { beforeEach, describe, expect, it } from 'vitest';
import {
  clearGlobalLogger,
  computeHmacSha256,
  setGlobalLogger,
  verifyWebhook,
  WebhookVerificationEvent,
} from '../src/index.js';
import { bytesToHex } from '../src/utils/encoding.js';

describe('Verification Telemetry & Logging Hooks', () => {
  const secret = 'telemetry_secret_key_123';
  const body = JSON.stringify({ event: 'payment.success' });

  beforeEach(() => {
    clearGlobalLogger();
  });

  it('should dispatch event to global logger on valid verification', async () => {
    const events: WebhookVerificationEvent[] = [];
    setGlobalLogger((evt) => {
      events.push(evt);
    });

    const timestamp = Math.floor(Date.now() / 1000);
    const payloadToSign = `${timestamp}.${body}`;
    const hmac = await computeHmacSha256(secret, payloadToSign);
    const signature = `t=${timestamp},v1=${bytesToHex(hmac)}`;

    const req = {
      headers: { 'stripe-signature': signature },
      body,
    };

    const result = await verifyWebhook('stripe', req, secret, { now: timestamp });
    expect(result.valid).toBe(true);

    expect(events.length).toBe(1);
    expect(events[0].provider).toBe('stripe');
    expect(events[0].valid).toBe(true);
    expect(events[0].timestamp).toBe(timestamp);
    expect(typeof events[0].durationMs).toBe('number');
    expect(events[0].durationMs).toBeGreaterThanOrEqual(0);
    expect(typeof events[0].attemptedAt).toBe('number');
  });

  it('should dispatch event to global logger on verification failure', async () => {
    const events: WebhookVerificationEvent[] = [];
    setGlobalLogger((evt) => {
      events.push(evt);
    });

    const req = {
      headers: { 'stripe-signature': 'invalid_sig' },
      body,
    };

    const result = await verifyWebhook('stripe', req, secret);
    expect(result.valid).toBe(false);

    expect(events.length).toBe(1);
    expect(events[0].provider).toBe('stripe');
    expect(events[0].valid).toBe(false);
    expect(events[0].code).toBe('MISSING_HEADER');
    expect(events[0].reason).toContain('Invalid "stripe-signature" header format');
  });

  it('should dispatch event to per-call onVerify logger callback', async () => {
    const perCallEvents: WebhookVerificationEvent[] = [];

    const req = {
      headers: { 'stripe-signature': 'invalid_sig' },
      body,
    };

    await verifyWebhook('stripe', req, secret, {
      onVerify: (evt) => {
        perCallEvents.push(evt);
      },
    });

    expect(perCallEvents.length).toBe(1);
    expect(perCallEvents[0].valid).toBe(false);
    expect(perCallEvents[0].provider).toBe('stripe');
  });

  it('should dispatch to both global and per-call logger callbacks simultaneously', async () => {
    const globalEvents: WebhookVerificationEvent[] = [];
    const perCallEvents: WebhookVerificationEvent[] = [];

    setGlobalLogger((evt) => {
      globalEvents.push(evt);
    });

    const req = {
      headers: { 'x-hub-signature-256': 'invalid' },
      body,
    };

    await verifyWebhook('github', req, secret, {
      log: (evt) => {
        perCallEvents.push(evt);
      },
    });

    expect(globalEvents.length).toBe(1);
    expect(perCallEvents.length).toBe(1);
    expect(globalEvents[0].provider).toBe('github');
    expect(perCallEvents[0].provider).toBe('github');
  });

  it('should safely swallow exceptions thrown by logger callbacks without breaking verifyWebhook', async () => {
    setGlobalLogger(() => {
      throw new Error('Logger exploded!');
    });

    const req = {
      headers: { 'stripe-signature': 'invalid' },
      body,
    };

    const result = await verifyWebhook('stripe', req, secret, {
      onVerify: async () => {
        throw new Error('Async logger exploded!');
      },
    });

    expect(result.valid).toBe(false);
    expect(result.code).toBe('MISSING_HEADER');
  });
});
