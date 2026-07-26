# Changelog

All notable changes to the `verihook` project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
