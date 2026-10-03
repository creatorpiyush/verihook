# Changelog

All notable changes to the `verihook` project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Property-based fuzz tests with fast-check (`npm run test:fuzz`): random requests never verify or throw, any signed payload verifies, and any change to a signed body is rejected.
- CodeQL static analysis on pull requests, on `main` and weekly.
- Dependabot for npm (root and example apps) and GitHub Actions.

### Changed
- Example apps upgraded to current majors (Next.js 16, React 19, Express 5, Fastify 5, `@hono/node-server` 2), clearing the advisories in their lockfiles. The Next.js route awaits `params`, as Next.js 15+ requires.
- vitest 4.1.11 fixes the moderate dev-only advisory in `@vitest/mocker`. `npm audit` now reports no vulnerabilities.
- `scripts/pre-commit.sh` and `scripts/pre-release.sh` install with `npm ci` (lockfile-pinned) instead of `npm install`.

## [1.14.0] - 2026-10-03

### Added
- 🪶 **Per-provider entry points.** Every provider has its own subpath (`verihook/stripe`, `verihook/github`, `verihook/svix`, ...) exporting its `verify*` functions, verifier, event type and `WebhookErrorCode`. `verifyStripe` from `verihook/stripe` is ~4 kB (min + brotli) against ~10 kB for `verifyWebhook` with every provider.
- `"sideEffects": false` in `package.json`, so bundlers can drop unused modules.
- Bundle size budgets in CI (`npm run size`, size-limit).
- Cross-SDK conformance tests against the official Stripe, Octokit, Svix and Twilio SDKs, in both directions (`npm run test:conformance`).
- OpenSSF Scorecard workflow and badge. The coverage badge now comes from CI instead of a hardcoded value.

### Changed
- The build emits shared code as chunks (`splitting: true`) instead of copying the core into every entry. The published package drops from 1.7 MB to about 0.35 MB, and the main entry, adapters and CLI work as before.
- GitHub Actions are pinned to commit SHAs, and workflow tokens default to read-only.

## [1.13.0] - 2026-10-03

### Added
- 🛠️ **Developer tools & SaaS providers.** Each has a `verify*` shortcut, a typed event, `signWebhook()` and `npx verihook simulate` support, and tests with known-good vectors:
  - `gitlab` (`verifyGitLab`): signing tokens (Standard Webhooks `webhook-*` headers, GitLab 19.1+) and legacy `x-gitlab-token` secret tokens.
  - `bitbucket` (`verifyBitbucket`): Bitbucket Cloud and Data Center `x-hub-signature`. `eventType` comes from `x-event-key`.
  - `vercel` (`verifyVercel`): HMAC-SHA1 `x-vercel-signature`.
  - `sentry` (`verifySentry`): `sentry-hook-signature`. `eventType` is `<resource>.<action>`, e.g. `issue.created`.
  - `twitch` (`verifyTwitch`): EventSub signatures with a 10-minute default tolerance, as Twitch recommends.
  - `telegram` (`verifyTelegram`): the `setWebhook` secret token. `eventType` is the update kind.
  - `postmark` (`verifyPostmark`): Basic auth credentials. Postmark doesn't sign webhooks.
  - `sendgrid` (`verifySendGrid`): signed Event Webhook (ECDSA P-256), verified with Web Crypto.
  - `mailgun` (`verifyMailgun`): the body signature for JSON webhooks and form posts. Dedupe keys on the signature token.
  - `hubspot` (`verifyHubSpot`): v3, v2 and v1 signatures. v2 and v3 sign the request URL.
  - `intercom` (`verifyIntercom`): HMAC-SHA1 `x-hub-signature`.
  - `calendly` (`verifyCalendly`): `t=...,v1=...` signatures with a 3-minute default tolerance, as Calendly recommends.
  - `typeform` (`verifyTypeform`): base64 `typeform-signature`.
- `verifyEcdsaP256Sha256()` crypto helper (DER signatures, base64 SPKI or PEM keys).
- Dedupe uses `twitch-eventsub-message-id`, GitLab's `idempotency-key`, Standard Webhooks' `webhook-id` and Mailgun's signature token.
- `signWebhook("sendgrid")` generates a throwaway P-256 key pair (or takes `privateKey`) and returns the public key as `secret`, like Discord.

## [1.12.0] - 2026-10-03

### Added
- 🌍 **Regional payment providers** for India, Europe and the USA. Each has a `verify*` shortcut, a typed event, `signWebhook()` and `npx verihook simulate` support, and tests with known-good vectors:
  - 🇮🇳 `cashfree` (`verifyCashfree`): HMAC-SHA256 of `<timestamp><body>`, base64, with replay protection.
  - 🇮🇳 `phonepe` (`verifyPhonePe`): checks the `authorization` hash of the webhook credentials. Pass `"username:password"` as the secret. PhonePe doesn't sign the body.
  - 🇪🇺 `mollie` (`verifyMollie`): next-gen `x-mollie-signature`. Either signature is accepted during secret rotation.
  - 🇪🇺 `adyen` (`verifyAdyen`): standard notifications (every item's `hmacSignature` must verify) and `HmacSignature`-header webhooks. The secret is the hex HMAC key.
  - 🇪🇺 `checkout` (`verifyCheckout`): Checkout.com `cko-signature`.
  - 🇺🇸 `authorizenet` (`verifyAuthorizeNet`): HMAC-SHA512 `x-anet-signature`.
  - 🇺🇸 `recurly` (`verifyRecurly`): `recurly-signature` with millisecond timestamps, key rotation and replay protection. `eventType` is `<object_type>.<event_type>`.
- Dedupe uses Authorize.net's `notificationId` as the event key.
- Wrong-provider hints now recognize the Mollie, Adyen, Checkout.com, Authorize.net and Recurly signature headers.

## [1.11.0] - 2026-10-03

### Added
- 🧩 **Framework adapters**: new subpath exports, each with no runtime dependency on its framework:
  - `verihook/fastify`: `verihookFastify()` `preHandler` hook, plus the `verihookRawBody` plugin. The plugin keeps `request.rawBody` and still parses JSON and form bodies.
  - `verihook/hono`: `verihookHono()` middleware. It sets `c.get("verihook")`; type it with `VerihookVariables<TEvent>`.
  - `verihook/h3`: `createWebhookHandler()` for Nuxt / Nitro / h3 v1 and v2.
  - `verihook/sveltekit`, `verihook/remix` (also React Router), `verihook/astro`: `createWebhookHandler()` route handlers.
  - `verihook/lambda`: `createWebhookHandler()` for API Gateway REST (v1), HTTP API (v2) and Function URLs. It decodes base64 bodies and rebuilds the signed URL for Twilio and Square.
  - `verihook/nestjs`: `createVerihookGuard()`. It uses Nest's `rawBody: true` and works on the Express and Fastify platforms; pass an optional `exceptionFactory`.
- All adapters share the Express/Next.js contract:
  - 401 on failure, or `onError`;
  - 200 `{ received: true, duplicate: true }` for duplicates;
  - 413 above `maxBodySize`;
  - a generic 500 on exceptions;
  - the dedupe key is released when your handler throws or responds `>= 500`.

### Changed
- `verihook/next` now runs on the shared Web adapter core (`src/middleware/shared.ts`). Behaviour is unchanged.
- The Fastify and Hono examples use the new adapters.

## [1.10.0] - 2026-10-03

### Added
- 🏷️ **Typed events**: Verified results now include `event` and `eventType`. Failed results never carry the payload.
  - `event` is the parsed payload: JSON, or the fields of a form post.
  - `eventType` is the event name, read from wherever the provider puts it: the body (`type`, `event`, `event_type`, `meta.event_name`, …) or a header (GitHub `x-github-event`, Shopify `x-shopify-topic`).
  - Built-in providers have lightweight payload types (`StripeEvent`, `GitHubEvent`, `SvixEvent`, …, mapped in `ProviderEventMap`). They need no provider SDK.
  - Override the type with `verifyWebhook<MyEvent>(...)`, `verifyStripe<MyEvent>(...)` or `createWebhookHandler<MyEvent>(...)`.
  - Express adds `event` and `eventType` to `req.verihook`. Telemetry events include `eventType`.
  - Custom providers can define `eventType(event, req)`.
- `signWebhook("shopify")` sends `x-shopify-topic`, taken from `options.event` (default `orders/create`).
- 🤝 **Contributor on-ramp**:
  - `CONTRIBUTING.md` with "Add a provider in 5 steps";
  - a tested provider template (`src/providers/_template.ts`, not shipped);
  - issue forms for bugs, provider requests and framework requests;
  - a pull request template.

## [1.9.0] - 2026-10-03

### Added
- 🧪 **`verihook/testing`**: `signWebhook(provider, options)` returns a correctly signed `{ url, headers, body, secret }` for every built-in provider except PayPal. `createSignedRequest()` returns the same as a Fetch `Request`. Supports JSON or form bodies, fixed timestamps, Svix message IDs, Discord Ed25519 seeds and generic header, algorithm and encoding options.
- 🩺 **Troubleshooting hints**: Failed results may include `hint` with the likely cause and fix:
  - a body that was re-serialized or already consumed (checked against `content-length`);
  - a Stripe API key used instead of the `whsec_` signing secret, a non-`whsec_` Svix/Resend/Clerk secret, or a secret with whitespace or quotes;
  - headers from a different provider, or no headers at all;
  - a Twilio/Square signed-URL mismatch behind a proxy;
  - a replayed fixture with an expired timestamp.
  
  Hints are also on telemetry events and `WebhookVerificationError.hint`. Outside production and test runs, each distinct hint is printed once with `console.warn`. Hints are never included in middleware HTTP responses.

### Fixed
- 🛍️ **`npx verihook simulate shopify`** now sends a valid `x-shopify-hmac-sha256` signature. It previously fell through to the generic `x-signature` header and failed verification.

### Changed
- The CLI `simulate` command now signs through `signWebhook()`, so the CLI and the testing helpers share one implementation. Twilio JSON simulations are sent to the signed URL, including `bodySHA256`.

## [1.8.0] - 2026-10-02

### ⚠️ Upgrade Notes
- **PayPal**: Verification is RSA-SHA256 only. Requests are accepted only with a `paypal-cert-url` on a PayPal API host (or a PEM pinned as `secret`), and a webhook ID is required (`options.webhookId`). Integrations that relied on the HMAC fallback will now be rejected — that fallback was the vulnerability below.
- **Duplicate events**: `verihookExpress` / `createWebhookHandler` now answer duplicates with `200 { received: true, duplicate: true }` instead of `401`.
- **`MemoryDedupeStore`**: `maxSize` now defaults to `10_000` (previously unbounded).
- **500 responses**: Middleware error bodies are now a generic `"Internal webhook verification error"`; use `onError` or telemetry for details.
- **Twilio / Square**: Relative request URLs are now resolved from `x-forwarded-*`/`host` headers and `req.protocol` (default https); `options.url` still takes precedence.

### Security
- 💳 **PayPal: removed HMAC fallback (signature forgery)**: Requests without `paypal-cert-url` were verified with an HMAC keyed by `secret`; since the webhook ID is both the conventional `secret` and part of the signed payload, anyone knowing a webhook ID could forge events. PayPal never sends HMAC signatures, so verification is now RSA-SHA256 only.
  - `paypal-cert-url` must be `https` on an exact PayPal API host (`api.paypal.com`, `api-m.paypal.com`, and sandbox equivalents); the previous `*.paypal.com` suffix match is gone.
  - Certificate fetches use a 5s timeout, refuse redirects, and are cached per URL (`clearPayPalCertCache()` exported for tests).
  - A webhook ID (`options.webhookId`, or a non-PEM `secret`) is now required.
- 🙈 **No internal error details in responses**: Express and Next.js middlewares return a generic `500` message; the full error still reaches `onError` and telemetry.
- 🧱 **Provider registry**: `Object.prototype` members (`constructor`, `__proto__`, …) no longer resolve as providers, and `registerProvider` rejects reserved names.
- ⏱️ **Meta challenge** verify token is compared in constant time.

### Fixed
- 🔁 **Dedupe no longer drops retried events**: Express and Next.js middlewares answer duplicates with `200 { received: true, duplicate: true }` instead of `401`, and release the event when the handler fails (thrown error or 5xx). Added optional `DedupeStore.delete(key)` and `VerificationResult.dedupeKey`.
- 🌐 **Twilio & Square behind Express/proxies**: Relative request URLs (e.g. `req.originalUrl`) are rebuilt into the public URL from `x-forwarded-proto`/`x-forwarded-host`/`host`, using `req.protocol` (Express/Fastify) when no forwarded protocol is present, else https. Twilio now signs the exact URL string instead of re-serializing it, and accepts URLs with or without the default port. Mismatch reasons include the signed URL to make misconfiguration obvious.
- 📏 **Next.js body limit**: `createWebhookHandler` enforces `maxBodySize` (default 2MB, `413 PAYLOAD_TOO_LARGE`) and reads the body once instead of twice.
- 🔄 **Secret rotation**: Paddle (`h=`) and WorkOS (`v1=`) accept any of multiple signatures in the header.
- 🏷️ **Error codes**: Non-verihook error codes thrown during verification (e.g. Node's `ERR_*`) are reported as `UNKNOWN_ERROR`.
- 🧠 **`MemoryDedupeStore` memory bound**: `maxSize` now defaults to 10,000 and expired entries are swept on insert.
- 🧰 **CLI `--flag=value` parsing** no longer truncates values containing `=` (base64 secrets, URLs with query strings).
- 🧪 **CLI `simulate`** now produces verifiable webhooks for Square, Zoom, Linear, Razorpay, Discord (generated Ed25519 key pair, public key printed) and generic (`x-signature` header). PayPal simulation is refused with an explanation.
- 📦 **Package exports**: Added `"./package.json"` to `exports` so tooling can read `verihook/package.json`.
- 🧩 **Examples**: Typed the Hono worker's `WEBHOOK_SECRET` binding so the example typechecks.
- 🐚 **CLI** `--curl` output is shell-quoted, and the banner shows the real package version instead of a hardcoded `v1.7.0`.

## [1.7.3] - 2026-08-16

### Fixed
- 💳 **PayPal RSA Certificate & HMAC Fallback**:
  - Prioritized user-supplied PEM public keys in `secret` over raw header URL strings.
  - Added strict origin domain validation (`*.paypal.com` / `*.paypal.cn`) for `paypal-cert-url` before certificate fetching.
  - Ensured non-PEM HMAC secret keys correctly fall back to HMAC signature verification even when `paypal-cert-url` is present in headers.
- ⏱️ **Millisecond Timestamp Normalization (Webflow, Zoom, and `options.now`)**:
  - Added `toEpochSeconds` timestamp utility to normalize 13-digit millisecond timestamps (> `1e10`) to seconds.
  - Applied `toEpochSeconds` across Webflow (`x-webflow-timestamp`), Zoom (`x-zm-request-timestamp`), Stripe, Slack, Svix, Discord, Paddle, and WorkOS verifiers.
  - Ensured `options.now` supports timestamps passed in either seconds or milliseconds (`Date.now()`).
- 🛡️ **Safe Key-Value Header Parameter Splitting**:
  - Refactored header parsing in Stripe, WorkOS, Paddle, and Svix verifiers using `indexOf("=")` to safely handle parameters without `=` or values containing internal `=` characters.
- 🔐 **Cryptographic Guard & Encoding Format Validation**:
  - Added null, undefined, and type safety checks to `timingSafeEqual` to prevent runtime `TypeError` on malformed inputs.
  - Added regex `/^[0-9a-fA-F]*$/` format validation to `hexToBytes` to throw format errors for non-hex characters instead of coercing `NaN` to `0x00`.
- 🧠 **MemoryDedupeStore LRU Access Order Refresh**:
  - Updated `MemoryDedupeStore.hasOrSet` to refresh key access order in the internal `Map` on duplicate hits, preserving true LRU eviction order under load.
- 🌐 **CLI SSRF Validation & Security Standards**:
  - Expanded `isPrivateNetworkHost` in `src/cli/index.ts` to cover `0.0.0.0`, `0`, IPv6 loopback `::1` (`[::1]`), octal `0177.0.0.1`, hex `0x7f000001`, and decimal `2130706433`.
  - Replaced dynamic `new Function` usage in `isDirectRun()` with static module checks to comply with strict security standards.
- 🌐 **Non-Node Runtime Process Safety**:
  - Added safe `typeof process !== "undefined"` guards in `dispatchTelemetry` to prevent `ReferenceError` when executed in browser or edge worker runtimes.

---

## [1.7.2] - 2026-08-11

### Added
- 🌐 **Distributed Deduplication Examples & Serverless Edge Callouts**:
  - Added copy-pasteable reference implementations in `examples/dedupe-stores/`:
    - `examples/dedupe-stores/upstash-redis.ts`: REST/Fetch-based Upstash Redis `DedupeStore` for zero-TCP edge runtimes (Cloudflare Workers, Vercel Edge).
    - `examples/dedupe-stores/cloudflare-kv.ts`: Cloudflare Workers KV-backed `DedupeStore` for edge deployments.
  - Configured `examples/dedupe-stores/` as a standalone Node.js ES module project (`package.json`, `tsconfig.json`, `index.ts`).
  - Added multi-instance & serverless callout documentation in `README.md` clarifying `MemoryDedupeStore` single-process boundaries.

### Documentation
- 🛡️ **SSRF Defense-in-Depth Framing & Best-Effort Disclaimers**:
  - Updated `SECURITY.md`, `README.md`, `ARCHITECTURE.md`, and `src/cli/index.ts` JSDoc comments to clarify that application-level IP/host denylisting is a best-effort defense-in-depth measure against known cloud metadata IPs and encoding bypasses.
  - Explicitly documented that host denylists are inherently incomplete and are not a substitute for network-level egress isolation (e.g., VPC security groups, egress proxies, or firewall rules).

---

## [1.7.1] - 2026-08-11

### Added
- 🛡️ **Security Policy & Vulnerability Disclosure (`SECURITY.md`)**:
  - Added formal `SECURITY.md` defining supported versions, private disclosure channels (GitHub Security Advisories & security email), response SLA commitments, core security architectural guarantees (constant-time verification, SSRF origin hardening, stream body limits), and integration best practices.

### Changed
- 🔌 **Provider-Declared Secret Requirement (`requiresSecret`)**:
  - Added optional `requiresSecret?: boolean` field to `ProviderVerifier` interface (defaults to `true`).
  - Explicitly set `requiresSecret: false` on `paypalVerifier` to document certificate/RSA-based authentication.
  - Removed hardcoded `provider !== "paypal"` string check from core verifier dispatcher in `src/core/verifier.ts`.

### Fixed
- 🐛 **Unknown Provider Verification Error Precedence**:
  - Reordered core `verifyWebhook` flow to resolve `getProviderVerifier(provider)` before checking secret presence.
  - Calling `verifyWebhook` with an unsupported provider and no secret now correctly returns `UNSUPPORTED_PROVIDER` instead of `INVALID_SECRET`.

---

## [1.7.0] - 2026-08-09

### Added
- 📡 **Live Local Relay Proxy (`npx verihook listen`)**:
  - Live local HTTP relay proxy subcommand `npx verihook listen <provider> --forward-to <url> [options]`.
  - Zero-dependency real-time signature verification, colorized terminal log output (request method, path, timestamp, provider, header redaction, and payload snippet), and HTTP forwarding to local application servers.
  - Proxy configuration options `--forward-to`, `--port` / `-p`, `--secret`, `--path`, and `--allow-remote`.
- ⚙️ **CLI Subcommand Parser & Schema Validation**:
  - Extended `ParsedCliArgs` interface and `validateCliArgs` schema validator in `src/schemas/index.ts` to support `command` (`simulate` | `listen`), `forwardTo`, `port`, and `path`.
- 🧪 **Live Relay Test Suite (`tests/cli-listen.test.ts`)**:
  - Added full test suite validating proxy server initialization, real-time signature verification, HTTP request forwarding, Bad Gateway (502) error handling, and SSRF prevention.

---

## [1.6.0] - 2026-08-09

### Added
- 🛡️ **Replay Protection & Event Deduplication Store (`MemoryDedupeStore`, `dedupeStore`)**:
  - Added pluggable `DedupeStore` interface and built-in high-performance `MemoryDedupeStore` with configurable TTL (`ttlMs`) and capacity bounds (`maxSize`).
  - Provider-aware automatic event ID extraction (`extractEventId`) supporting `svix-id`, `x-github-delivery`, `x-shopify-webhook-id`, `paypal-transmission-id`, JSON body IDs (`id`, `event_id`, `msg_id`, `messages[0].id`), signature fallback headers, and SHA-256 payload hashing.
  - Added `DUPLICATE_EVENT` error code (`WebhookErrorCode.DUPLICATE_EVENT`) returned on duplicate event detection.
  - Added options `dedupeStore`, `dedupeTtlMs`, and `eventId` to `VerifyWebhookOptions`.
- 🧪 **Deduplication Test Suite (`tests/dedupe.test.ts`)**:
  - Added test suite achieving 100% line coverage across store operations, TTL expiration, capacity eviction, provider ID extraction, and verification rejection.

---

## [1.5.1] - 2026-08-09

### Fixed
- 🐛 **Express Middleware TypeScript Typings (`verihookExpress`)**:
  - Resolved `No overload matches this call` type errors when registering `verihookExpress` with Express `app.use()` and `app.post()` by removing string index signature from `ExpressRequestLike` and explicitly annotating middleware return type as `Promise<void>`.

---

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
