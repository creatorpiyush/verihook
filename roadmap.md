# Future Roadmap & Feature Expansion Plan — `verihook` 🪝

This plan outlines high-value, developer-first feature proposals and provider additions for future releases of `verihook`.

---

## 1. Provider Ecosystem Expansion (v1.2.0)

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

## 2. One-Line Framework Middlewares (v1.3.0)

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

## 3. CLI Enhancements — `npx verihook listen` & Webhook Inspector (v1.4.0)

Expand the CLI simulator into a full local developer toolchain:

### A. Live Local Relay Proxy (`npx verihook listen`)
- **Command**:
  ```bash
  npx verihook listen stripe --forward-to http://localhost:3000/webhooks/stripe
  ```
- **Functionality**:
  - Acts as a local inspector.
  - Intercepts incoming webhooks, validates signatures in real time, and prints colorized output (Header, Timestamp, Payload Diff, Signature Match Status) in terminal before forwarding to your local server.

### B. Event Payload Presets (`npx verihook simulate`)
- Support event preset templates:
  ```bash
  npx verihook simulate stripe --event payment_intent.succeeded
  npx verihook simulate github --event pull_request
  npx verihook simulate whatsapp --event text_message
  ```

---

## 4. Replay Protection & Deduplication Store (v1.5.0)

Provide optional event deduplication state store to prevent duplicate event execution within tolerance windows:

```ts
import { verifyWebhook, MemoryDedupeStore } from 'verihook';

const dedupeStore = new MemoryDedupeStore({ ttlMs: 300_000 });

const result = await verifyWebhook('stripe', req, secret, {
  dedupeStore, // Automatically checks if event.id / svix-id was already processed!
});
```

---

## Priority & Phasing Summary

- **Phase 1 (v1.2.0)**: Add **PayPal, LemonSqueezy, Paddle, X/Twitter, PagerDuty, Webflow**.
- **Phase 2 (v1.3.0)**: Add **Express & Next.js middleware helpers**.
- **Phase 3 (v1.4.0)**: Add **`npx verihook listen` CLI inspector**.
- **Phase 4 (v1.5.0)**: Add **Replay protection / deduplication store**.
