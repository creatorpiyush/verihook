# Future Roadmap & Feature Expansion Plan — `verihook` 🪝

This plan outlines high-value, developer-first feature proposals and provider additions for future releases of `verihook`.

---

## 1. Provider Ecosystem Expansion (v1.2.0) — ✅ Completed

Add native verification for the remaining major SaaS platforms:

| Platform | Verification Specification | Category |
| :--- | :--- | :--- |
| **X / Twitter API** | HMAC-SHA256 CRC handshake (`sha256=...`) + GET CRC challenge response | Social & Comms |
| **PayPal** | RSA-SHA256 signature checking (`paypal-transmission-sig`) over cert chain | Payments |
| **LemonSqueezy** | HMAC-SHA256 (`x-signature`) | Payments / E-commerce |
| **Paddle** | Verifying `paddle-signature` (`ts=...;h=...`) using public key | Payments / SaaS |
| **PagerDuty** | HMAC-SHA256 (`x-pagerduty-signature`) | Infrastructure / DevOps |
| **Webflow** | HMAC-SHA256 (`x-webflow-signature`) | No-Code / CMS |
| **WorkOS** | Svix-compatible HMAC-SHA256 | Auth / Enterprise |

---

## 2. One-Line Framework Middlewares (v1.3.0) — ✅ Completed

Provide 1-line middleware abstractions for popular Node & Edge frameworks:

### Express Middleware
```ts
import { verihookExpress } from 'verihook/express';

app.post(
  '/webhooks/stripe',
  verihookExpress('stripe', process.env.STRIPE_SECRET!),
  (req, res) => {
    // req.verifiedPayload is guaranteed valid and raw body preserved!
    res.json({ status: 'ok' });
  }
);
```

### Next.js Route Handler Factory
```ts
import { createWebhookHandler } from 'verihook/next';

export const POST = createWebhookHandler('github', process.env.GITHUB_SECRET!, async (payload, result) => {
  // Executed ONLY if signature is 100% valid!
  await handleGitHubEvent(payload);
});
```

---

## 3. Verification Logging & Telemetry Hooks (v1.4.0) — ✅ Completed

Provide global and per-call verification event callbacks for logging every verification attempt (pass/fail/expired/invalid signature), designed for production observability (Datadog, Winston, Pino, Axiom, Console, Sentry, OpenTelemetry).

```ts
import { setGlobalLogger, verifyWebhook } from 'verihook';

// Global telemetry hook for all verifications in the application
setGlobalLogger((event) => {
  console.log(`[verihook] ${event.provider} - valid: ${event.valid} (${event.durationMs}ms)`);
  if (!event.valid) {
    console.warn(`[verihook] Verification failed: ${event.code} - ${event.reason}`);
  }
});

// Per-call logger override
const result = await verifyWebhook('stripe', req, secret, {
  onVerify: (event) => {
    // Structured telemetry event: { provider, valid, code, reason, timestamp, durationMs, attemptedAt, error }
    metrics.increment('webhook.verification', 1, { provider: event.provider, valid: String(event.valid) });
  },
});
```

---

## 4. CLI Event Simulator & E2E Verification Suite (v1.5.0 / v1.5.1) — ✅ Completed

Expand the CLI simulator and verification ecosystem:

### A. CLI Event Simulator & cURL Generator (`npx verihook simulate`)
- Support event simulator and cURL generation across all 20+ supported webhook providers:
  ```bash
  npx verihook simulate stripe --curl
  npx verihook simulate github --event push --curl
  npx verihook simulate slack --curl
  ```

### B. Master E2E Test Suite & Strict Express Typings
- Master E2E test runner (`scripts/test-all.sh`) validating linting, formatting, coverage (>95%), CJS/ESM module loading, and CLI execution.
- Express middleware strict TypeScript typing fix (`verihookExpress`) for seamless integration with Express `app.use()` and `app.post()`.

---

## 5. Replay Protection & Deduplication Store (v1.6.0) — ✅ Completed

Provide optional event deduplication state store to prevent duplicate event execution within tolerance windows:

```ts
import { verifyWebhook, MemoryDedupeStore } from 'verihook';

const dedupeStore = new MemoryDedupeStore({ ttlMs: 300_000 });

const result = await verifyWebhook('stripe', req, secret, {
  dedupeStore, // Automatically checks if event.id / svix-id was already processed!
});
```

---

## 6. Live Local Relay Proxy — `npx verihook listen` (v1.7.0) — ✅ Completed

Expand the CLI toolchain into a live local developer relay proxy:

- **Command**:
  ```bash
  npx verihook listen stripe --forward-to http://localhost:3000/webhooks/stripe
  ```
- **Functionality**:
  - Intercepts incoming webhooks, validates signatures in real time, and prints colorized output (Headers, Timestamp, Signature Match Status) in terminal before forwarding to your local server.
  - Supports forwarding specific event preset templates (e.g. `--event payment_intent.succeeded`).

---

## Priority & Phasing Summary

- **Phase 1 (v1.2.0)**: Add **PayPal, LemonSqueezy, Paddle, X/Twitter, PagerDuty, Webflow**. ✅
- **Phase 2 (v1.3.0)**: Add **Express & Next.js middleware helpers**. ✅
- **Phase 3 (v1.4.0)**: Add **Verification Logging & Telemetry Hooks (`setGlobalLogger`, `onVerify`)**. ✅
- **Phase 4 (v1.5.0 / v1.5.1)**: Add **CLI Simulator, E2E Test Suite & Express TS Typing fix**. ✅
- **Phase 5 (v1.6.0)**: Add **Replay protection / deduplication store (`MemoryDedupeStore`)**. ✅
- **Phase 6 (v1.7.0)**: Add **`npx verihook listen` live local relay proxy**. ✅

