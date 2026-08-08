# Changelog

All notable changes to the `verihook` project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.5.0] - 2026-08-08

### Added
- 🧪 **Master End-to-End Test Suite (`npm run test:all`)**:
  - Added automated test runner script `scripts/test-all.sh` (`npm run test:all`) performing Prettier formatting checks, TypeScript strict typechecks, V8 coverage verification, regression tests, production build verification, CLI binary simulations, and live CommonJS & ESM module export validation.
- 🛡️ **Full End-to-End Regression Suite (`npm run test:regression`)**:
  - Added [tests/regression.test.ts](file:///Users/piyush.anand/self_code/verihook/tests/regression.test.ts) covering all 20+ signature algorithms, security negative paths, custom plugin registration, Express & Next.js adapters, and CLI simulator cURL generation across 162 total unit tests.
- 🏷️ **Documentation Badges & Verification**:
  - Added Shields.io badges in `README.md` for GitHub CI workflow status, 96% code coverage, zero dependencies, TypeScript strict mode, and monthly npm downloads.

### Changed
- 📊 **Code Coverage Push (>95% Lines / 99% Providers)**:
  - Boosted V8 code coverage to **95.93% line coverage** and **99.29% provider coverage**, achieving **100% line coverage** across `src/core/verifier.ts`, `src/schemas/index.ts`, and 17 provider modules.
- ⚡ **CLI Direct Execution Guard (`isDirectRun`)**:
  - Upgraded entry point direct execution detection in `src/cli/index.ts` to use `fs.realpathSync` path matching against `require.main` and `import.meta.url` to prevent test framework pollution and avoid accidental execution in user applications.

### Security
- 🔒 **Transitive Dependency Remediation**:
  - Added `overrides: { "esbuild": "0.28.1" }` in `package.json` to remediate high-severity vulnerability GHSA-g7r4-m6w7-qqqr.

---

## [1.4.0] - 2026-08-02

### Added
- 📊 **Verification Logging & Telemetry Hooks (`setGlobalLogger`, `onVerify`)**:
  - Global application-wide telemetry callback via `setGlobalLogger(loggerFn)` and `getGlobalLogger()`.
  - Per-verification telemetry callback options `onVerify` and `log` in `VerifyWebhookOptions`.
  - Structured `WebhookVerificationEvent` payload containing `provider`, `valid`, `code`, `reason`, `timestamp`, `durationMs`, `attemptedAt`, and optional `error`.
  - Isolated exception handling ensuring logging callback errors never affect verification results or throw unhandled exceptions.
  - Native performance measurement using high-resolution `performance.now()`.
- 🧪 **Telemetry Test Suite (`tests/telemetry.test.ts`)**:
  - Added test suite for global & per-call telemetry dispatching, timing metadata accuracy, and exception safety, bringing total test suite to **100 unit tests** across 28 test files.

---

## [1.3.1] - 2026-08-01

### Fixed
- 🔐 **RSA Signature Decoding**: Fixed Base64 format detection in `verifyRsaSha256` for signatures that do not contain `=` padding or `/` characters.
- 🛡️ **Base64 Fallback Validation**: Updated `base64ToBytes` with explicit character set and length validation so non-base64 secrets cleanly fall back to UTF-8 bytes in `svixVerifier` across Node.js and browser environments.
- 🔤 **Generic Verifier Hex Case-Insensitivity**: Added lowercase normalization to `genericVerifier` when matching hex and prefix-hex signature headers.
- 🔁 **Twilio Multi-Value Form Parameter Signing**: Deduplicated parameter key names using `Set` in `twilioVerifier` to properly sort and sign multi-value form parameters.
- 💥 **WorkOS & Paddle Header Parsing Safety**: Added safe key-value checks (`k && v`) in `workosVerifier` and `paddleVerifier` to avoid unhandled `TypeError` exceptions on malformed header strings.
- ✂️ **GitHub Signature Header Trimming**: Added whitespace trimming to `githubVerifier` before inspecting signature prefixes (`sha256=`, `sha1=`).
- ⚡ **CLI Twilio Simulation URL Formatting**: Fixed query delimiter (`?` vs `&`) logic when simulating Twilio webhooks against target URLs that contain query parameters.

### Added
- 🧪 **Regression Test Suite Additions**: Added unit tests covering RSA Base64 signature parsing, uppercase hex matching, multi-value form parameters, malformed headers, and CLI simulation handling, bringing total test count to **95 unit tests** across 27 test files.

---

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
