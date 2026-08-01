# Changelog

All notable changes to the `verihook` project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] - 2026-08-01

### Added
- 🚀 **1-Line Express Middleware (`verihookExpress`)**:
  - Subpath import `verihook/express` and root export `import { verihookExpress } from 'verihook'`.
  - Automatic stream buffering if request body has not been read yet.
  - Attaches `req.verihook` (`{ valid, provider, payload, timestamp }`) and `req.verifiedPayload`.
  - Automatic HTTP 401 response handling with structured error payload or custom `onError` handler.
  - Dynamic secret resolution via `secret: (req) => string | Promise<string>`.
- ⚡ **1-Line Next.js Route Handler Factory (`createWebhookHandler`)**:
  - Subpath import `verihook/next` and root export `import { createWebhookHandler } from 'verihook'`.
  - Compatible with Next.js App Router (`export const POST = createWebhookHandler(...)`) and Web API `Request`/`Response`.
  - Safe payload parsing via `req.clone()` without stream corruption.
  - Automatic HTTP 200/401 `Response` creation with custom `onError` and dynamic secret support.
- 📦 **Subpath Exports**:
  - Configured tree-shakeable subpath exports `./express` and `./next` in `package.json` and `tsup.config.ts`.
- 🧪 **Expanded Test Suite**:
  - Added full Vitest test suites `express-middleware.test.ts` and `next-middleware.test.ts`, bringing total test count to **87 unit tests** across 27 test files.

---

## [1.2.1] - 2026-07-26

### Fixed
- ⚡ **CLI Binary Invocation**: Fixed entry point invocation in `src/cli/index.ts` so `npx verihook simulate <provider>` executes unconditionally when invoked via `npx` or bin wrapper symlink.

---

## [1.2.0] - 2026-07-26

### Added
- 🐦 **Twitter / X API (`'twitter'`, `'x'`)**:
  - `x-twitter-webhooks-signature` HMAC-SHA256 signature verification (`verifyTwitter` / `verifyX`).
  - `verifyTwitterCrc(crcToken, consumerSecret)` helper for GET CRC challenge handshake.
- 💳 **PayPal (`'paypal'`)**:
  - `verifyPayPal` signature verification using transmission headers (`transmissionId|time|webhookId|crc32`).
  - RSA-SHA256 public certificate / key signature verification with zero runtime dependencies.
- 🍋 **LemonSqueezy (`'lemonsqueezy'`)**:
  - `x-signature` HMAC-SHA256 signature verification (`verifyLemonSqueezy`).
- 🏓 **Paddle (`'paddle'`)**:
  - `paddle-signature` (`ts=...;h=...`) signature verification (`verifyPaddle`).
- 🚨 **PagerDuty (`'pagerduty'`)**:
  - `x-pagerduty-signature` (`v1=...`) HMAC-SHA256 signature verification (`verifyPagerDuty`).
- 🕸️ **Webflow (`'webflow'`)**:
  - `x-webflow-signature` HMAC-SHA256 signature verification (`verifyWebflow`).
- 💼 **WorkOS (`'workos'`)**:
  - `workos-signature` (`t=...,v1=...`) / Svix-compatible webhook verification (`verifyWorkOS`).
- ⚡ **CLI Expansion**:
  - Updated CLI simulator (`npx verihook simulate`) to support all 7 new providers.
- 🧮 **New Utilities**:
  - Added `computeCrc32` and `verifyRsaSha256` in core exports.

### Changed
- Expanded unit test suite to **76 unit tests** passing across 25 test files.

---

## [1.1.0] - 2026-07-26

### Added
- 💬 **WhatsApp / Meta Webhook Support (`'meta'`, `'whatsapp'`, `'facebook'`, `'instagram'`)**:
  - Signature verification for `x-hub-signature-256` (`sha256=hex_digest`) via `verifyMeta` and `verifyWhatsApp`.
  - Added `verifyMetaChallenge(query, verifyToken)` helper to handle Meta's initial GET challenge handshake in Meta App Dashboard.
- 🎮 **Discord Interactions Support (`'discord'`)**:
  - Signature checking for `x-signature-ed25519` and `x-signature-timestamp` over `${timestamp}${rawBody}` using Ed25519 public key verification (`verifyDiscord`).
  - Native Web Crypto API `crypto.subtle` Ed25519 verification with zero runtime dependencies.
- ⚡ **CLI Simulator Tool (`npx verihook simulate`)**:
  - New built-in CLI tool to simulate signed webhooks locally without needing real third-party accounts.
  - Supports `--url`, `--secret`, `--event`, and `--curl` output flags across all 12+ providers.
- 🔐 **Core Exports**:
  - Exported `verifyEd25519` and `computeSha256` in main library entry point.

### Changed
- Expanded total test coverage to **63 unit tests** passing across 18 test files.

---

## [1.0.1] - 2026-07-26

### Fixed
- Fixed missing `README.md` in npm package distribution by adding `README.md` and `LICENSE` explicitly to `"files"` array in `package.json`.

---

## [1.0.0] - 2026-07-26

### Added
- Initial release of `verihook`: Universal typed webhook signature verifier.
- Built-in support for **Stripe, GitHub, Shopify, Slack, Twilio, Svix, Resend, Clerk, Linear, Razorpay, Zoom, Square, and Generic** webhooks.
- Structured `WebhookErrorCode` enum (`INVALID_SIGNATURE`, `EXPIRED_TIMESTAMP`, `MISSING_HEADER`, `MISSING_URL`, `INVALID_SECRET`, `INVALID_BODY`, `UNSUPPORTED_PROVIDER`, `UNKNOWN_ERROR`).
- Typed domain error classes: `WebhookVerificationError`, `InvalidBodyError`, `UnsupportedProviderError`.
- Support for Twilio JSON `bodySHA256` signature flow.
- Universal framework request normalizer (`normalizeRequest`) for Fetch API `Request`, Node.js `req`, Express, Next.js, Hono, Fastify, Cloudflare Workers.
- Zero external runtime dependencies.
