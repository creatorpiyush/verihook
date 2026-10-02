# Architecture & Technical Specification — `verihook` 🪝

> **Universal, typed webhook signature verifier** for TypeScript and JavaScript.

This document details the architectural design, security mechanisms, request normalization pipeline, type system, provider verification specification, and CLI developer toolchain of `verihook`.

---

## 1. Executive Overview

`verihook` provides a unified, strongly-typed interface (`verifyWebhook(provider, req, secret)`) for verifying incoming webhook signatures across 20+ major SaaS providers (27 provider identifiers).

### Core Objectives
1. **Zero External Runtime Dependencies**: Powered by native Web Crypto API (`crypto.subtle`) with Node.js `node:crypto` fallback.
2. **Hardened Security**: Multi-layered defense including constant-time timing-safe equality checks, SSRF origin validation, unparsed stream payload byte limits (`maxBodySize`), and standard HTTP security headers (`nosniff`, `DENY`).
3. **Universal Framework Portability**: Seamlessly processes standard Fetch API `Request` objects, Node.js HTTP/Express `req`, Fastify, Next.js App Router, Hono, and Cloudflare Workers.
4. **Local Developer Toolchain**: Includes a CLI binary for simulating signed webhooks (`npx verihook simulate`) and a zero-dependency live local relay proxy (`npx verihook listen`) for real-time local webhook inspection and forwarding.
5. **Side-Channel Timing Protection**: Enforces constant-time string comparisons across all provider signature verification logic.
6. **Strict Type Safety**: Completely eliminates `any` types in favor of strict `unknown` guards, explicit interfaces, and zero-dependency boundary validation schemas.
7. **Edge Ready**: Runs identically across Node.js (>= 18), Vercel Edge, Cloudflare Workers, Deno, and Bun.

---

## 2. Request Lifecycle & Pipeline

```mermaid
flowchart TD
    A["Incoming Webhook Request / CLI Proxy"] --> B["normalizeRequest Engine"]
    B --> C{"Input Type?"}
    C -->|Fetch Request| D["Extract headers, clone body via text"]
    C -->|Express / Node req| E["Stream buffer (maxBodySize limit)"]
    C -->|Plain Object| F["Extract object headers & body"]
    D --> G["NormalizedWebhookRequest"]
    E --> G
    F --> G
    G --> H["verifyWebhook Provider Registry"]
    H --> I["Execute Provider Verifier"]
    I --> J["Compute HMAC / Ed25519 / RSA via Web Crypto"]
    J --> K["timingSafeEqual Comparison"]
    K --> L["Return VerificationResult"]
    L -->|CLI Listen Server| M["Log & Forward to Local App Server"]
    L -->|Framework Middleware| N["Execute App Route Handler"]
```

---

## 3. Core Architectural Components

### A. Universal Input Normalizer (`src/utils/normalize-request.ts`)
Different frameworks expose HTTP headers and raw bodies in varying formats:
- **Fetch API / Next.js / Cloudflare Workers**: `Request` object with `Headers` instance and `clone().text()`.
- **Express / Fastify**: `IncomingMessage` or plain object with `req.headers` and string/Buffer `rawBody`.

`normalizeRequest()` converts any valid request input into a canonical `NormalizedWebhookRequest`:

```ts
export interface NormalizedWebhookRequest {
  headers: Record<string, string>; // Lowercased header keys
  rawBody: string;                 // Original unparsed payload string
  url?: string;                    // Full request URL (if required for HMAC)
  method?: string;                 // HTTP Method
}
```

---

### B. Cross-Runtime Crypto Engine (`src/core/crypto.ts`)
Crypto operations rely on `globalThis.crypto.subtle` (Web Crypto API):

```ts
export async function computeHmac(
  algorithm: 'SHA-256' | 'SHA-1' | 'SHA-512',
  secret: string | Uint8Array,
  data: string | Uint8Array
): Promise<Uint8Array> {
  const secretBytes = typeof secret === 'string' ? stringToBytes(secret) : secret;
  const dataBytes = typeof data === 'string' ? stringToBytes(data) : data;

  const cryptoSubtle = globalThis.crypto?.subtle;
  if (cryptoSubtle) {
    const key = await cryptoSubtle.importKey(
      'raw',
      secretBytes as unknown as BufferSource,
      { name: 'HMAC', hash: { name: algorithm } },
      false,
      ['sign']
    );
    const signature = await cryptoSubtle.sign('HMAC', key, dataBytes as unknown as BufferSource);
    return new Uint8Array(signature);
  }

  // Fallback for Node.js environments lacking globalThis.crypto.subtle
  const nodeCrypto = await import('node:crypto');
  const nodeAlg = algorithm.replace('-', '').toLowerCase();
  const hmac = nodeCrypto.createHmac(nodeAlg, Buffer.from(secretBytes));
  hmac.update(Buffer.from(dataBytes));
  return new Uint8Array(hmac.digest());
}
```

---

### C. Timing-Safe Equality Comparison (`src/core/crypto.ts`)
To prevent side-channel timing attacks where an attacker measures HMAC comparison durations:

```ts
export function timingSafeEqual(a: string | Uint8Array, b: string | Uint8Array): boolean {
  const bytesA = typeof a === 'string' ? stringToBytes(a) : a;
  const bytesB = typeof b === 'string' ? stringToBytes(b) : b;

  if (bytesA.length !== bytesB.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < bytesA.length; i++) {
    result |= bytesA[i] ^ bytesB[i];
  }

  return result === 0;
}
```

---

### D. Zero-Dependency Boundary Validator (`src/schemas/index.ts`)
To maintain **zero runtime dependencies** while ensuring input type safety:
- Implements `validateCliArgs` and `validateVerifyWebhookOptions` for validating CLI flags and verification options.
- Validates payload size thresholds, algorithm enums (`'sha256' | 'sha1' | 'sha512'`), encoding strings (`'hex' | 'base64' | 'prefix-hex'`), CLI commands (`'simulate' | 'listen'`), port ranges (1–65535), and URL syntax without external packages.

---

### E. Extensible Provider Plugin System (`src/providers/index.ts`)
Every provider implements the `ProviderVerifier` interface:

```ts
export interface ProviderVerifier {
  name: ProviderName;
  verify(
    req: NormalizedWebhookRequest,
    secret: string,
    options?: VerifyWebhookOptions
  ): Promise<VerificationResult>;
}
```

Custom providers can be registered dynamically at runtime:

```ts
import { registerProvider } from 'verihook';

registerProvider({
  name: 'my-custom-service',
  async verify(req, secret) {
    // Custom verification logic...
    return { valid: true, provider: 'my-custom-service' };
  },
});
```

---

### F. Error Classification & Domain Errors (`src/core/errors.ts`)
`verihook` implements a structured error classification architecture:

#### 1. `WebhookErrorCode` Enum
All verifiers assign an explicit code from `WebhookErrorCode` to the `VerificationResult`:
- `WebhookErrorCode.INVALID_SIGNATURE`: HMAC digest mismatch.
- `WebhookErrorCode.EXPIRED_TIMESTAMP`: Timestamp outside tolerance window.
- `WebhookErrorCode.MISSING_HEADER`: Missing expected signature header.
- `WebhookErrorCode.MISSING_URL`: Missing request URL (required for Twilio / Square).
- `WebhookErrorCode.INVALID_SECRET`: Secret not provided.
- `WebhookErrorCode.INVALID_BODY`: Parsed object passed without `rawBody`.
- `WebhookErrorCode.UNSUPPORTED_PROVIDER`: Provider not recognized in registry.
- `WebhookErrorCode.UNKNOWN_ERROR`: Unexpected exception during verification.

#### 2. Domain Error Classes
- `WebhookVerificationError`: Thrown by `verifyWebhookOrThrow()`, contains `provider`, `reason`, and structured `code`.
- `InvalidBodyError`: Thrown when a pre-parsed JSON object is passed without `rawBody`.
- `UnsupportedProviderError`: Thrown when an unknown provider string is requested.

---

### G. Framework Middleware & Security Hardening (`src/middleware/`)
1-line middleware abstractions with built-in runtime hardening:

#### 1. Express Middleware (`verihookExpress`)
- **Location**: `verihook/express` (`src/middleware/express.ts`).
- **Stream Limit Protection**: Buffers unparsed body streams with an explicit `maxBodySize` threshold (default 2MB = 2,097,152 bytes), terminating stream consumption and returning HTTP 413 Payload Too Large if exceeded.
- **Security Headers**: Automatically sets `X-Content-Type-Options: nosniff` and `X-Frame-Options: DENY` on error responses.

#### 2. Next.js Route Handler Factory (`createWebhookHandler`)
- **Location**: `verihook/next` (`src/middleware/next.ts`).
- **Behavior**: Clones Web API `Request` objects, verifies signature, executes handler, and returns `Response` objects containing standard security headers (`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`).

---

## 4. SSRF Origin Protection Engine & CLI Toolchain (`src/cli/index.ts`)

The `verihook` CLI binary provides two core modes:

### A. Webhook Simulator (`npx verihook simulate <provider>`)
Synthesizes cryptographically valid payloads and headers for testing:
- Generates reproducible cURL commands (`--curl`).
- Sends signed test HTTP POST requests directly to target endpoints.

### B. Live Local Relay Proxy (`npx verihook listen <provider>`)
Zero-dependency HTTP proxy (`runListenServer`) for local development:
- Starts a local Node.js HTTP server (`http.createServer`) listening on `--port` (default 8080).
- Intercepts incoming webhooks, verifies signatures in real time (`verifyWebhook`), and formats terminal logs (Method, Path, Provider, Verification status, Redacted Secret Headers, Payload snippet).
- Forwards requests to local target applications (`--forward-to` / `http://localhost:3000/webhooks/<provider>`) and proxies HTTP response status, headers, and body back to the client. Returns HTTP 502 Bad Gateway if target application is unreachable.

### C. Multi-Layered SSRF Origin Guardrails
Both CLI commands enforce origin validation as a best-effort defense-in-depth measure (*not a substitute for network-level isolation*):
1. **Unconditional Cloud Metadata Blocking**:
   Blocks known cloud Instance Metadata Services (IMDS) and internal control plane hosts:
   - `169.254.169.254` (AWS, GCP, Azure, OpenStack, DigitalOcean, Alibaba)
   - `169.254.170.2` (AWS ECS Task Metadata)
   - `168.63.129.16` (Azure Wire Server IP)
   - `100.100.100.200` (Alibaba Cloud IMDS)
   - `metadata.google.internal` (GCP Metadata)
   - `metadata.tencentyun.com` (Tencent Cloud)
   - `kubernetes.default.svc` (Kubernetes Service CIDR)
2. **Subnet & Range Detection**:
   - `169.254.0.0/16` Link-Local IPv4 subnet range
   - `::ffff:169.254.x.x` IPv4-mapped IPv6 & `fe80::` IPv6 Link-Local
3. **Alternative Encoding Detection**:
   - Octal IP strings (e.g. `0251.0376.0251.0376`)
   - Integer / Hex representations (e.g. `2852039166`, `0xa9fea9fe`)
4. **Remote Host Guardrails**:
   - Disallows non-HTTP protocols (`file://`, `ftp://`, `gopher://`).
   - Requires `--allow-remote` or `VERIHOOK_ALLOW_REMOTE=true` when targeting non-local destinations.

> ⚠️ **Security Boundary Disclaimer**: Application-level denylist enumeration is a best-effort hardening layer against known cloud metadata endpoints and encoding tricks. Denylists do not replace network-level isolation (such as VPC egress controls, firewall rules, or DNS rebinding prevention) in production environments.

---

## 5. Provider Implementation Matrix

| Provider | Target Header | Algorithm & Encoding | Signature Base Payload | Replay Tolerance |
| :--- | :--- | :--- | :--- | :--- |
| **Stripe** | `stripe-signature` | HMAC-SHA256 / Hex | `${timestamp}.${rawBody}` | ✅ Default 300s |
| **GitHub** | `x-hub-signature-256` / `x-hub-signature` | HMAC-SHA256 / SHA1 Hex | `rawBody` | N/A |
| **Shopify** | `x-shopify-hmac-sha256` | HMAC-SHA256 / Base64 | `rawBody` | N/A |
| **Slack** | `x-slack-signature` | HMAC-SHA256 / Hex | `v0:${timestamp}:${rawBody}` | ✅ Default 300s |
| **Twilio** | `x-twilio-signature` | HMAC-SHA1 / Base64 | Form: `url + sortedKeysAndValues` <br> JSON: `url?bodySHA256=hashHex` | N/A |
| **Svix / Resend / Clerk** | `svix-signature` | HMAC-SHA256 / Base64 | `${svixId}.${svixTimestamp}.${rawBody}` | ✅ Default 300s |
| **Meta / WhatsApp** | `x-hub-signature-256` | HMAC-SHA256 / Hex | `rawBody` (Supports GET handshake) | N/A |
| **Discord** | `x-signature-ed25519` | Ed25519 / Hex | `${timestamp}${rawBody}` | ✅ Default 300s |
| **Twitter / X** | `x-twitter-webhooks-signature` | HMAC-SHA256 / Base64 | `rawBody` (Supports GET CRC handshake) | N/A |
| **PayPal** | `paypal-transmission-sig` | RSA-SHA256 / Base64 | `${transmissionId}|${time}|${webhookId}|${crc32}` | N/A |
| **LemonSqueezy** | `x-signature` | HMAC-SHA256 / Hex | `rawBody` | N/A |
| **Paddle** | `paddle-signature` | HMAC-SHA256 / Hex | `${ts}:${rawBody}` | ✅ Default 300s |
| **PagerDuty** | `x-pagerduty-signature` | HMAC-SHA256 / Hex | `rawBody` | N/A |
| **Webflow** | `x-webflow-signature` | HMAC-SHA256 / Hex | `${timestamp}:${rawBody}` or `rawBody` | ✅ Default 300s |
| **WorkOS** | `workos-signature` | HMAC-SHA256 / Hex | `${timestamp}.${rawBody}` | ✅ Default 300s |
| **Linear** | `linear-signature` | HMAC-SHA256 / Hex | `rawBody` | N/A |
| **Razorpay** | `x-razorpay-signature` | HMAC-SHA256 / Hex | `rawBody` | N/A |
| **Square** | `x-square-hmacsha256-signature` | HMAC-SHA256 / Base64 | `url + rawBody` | N/A |
| **Zoom** | `x-zm-signature` | HMAC-SHA256 / Hex | `v0:${timestamp}:${rawBody}` | ✅ Default 300s |
| **Generic** | Custom | Custom (SHA256/1/512, Hex/Base64) | `rawBody` | Optional |

---

## 6. Security & Build Hygiene

- **Automated Verification Pipeline**: `"test:all": "bash scripts/test-all.sh"` validates Prettier code style, strict TypeScript types, V8 unit test coverage (96%+), end-to-end regression suite, CJS/ESM/DTS tsup bundle generation, CLI simulate/listen execution, and module exports in sequence.
- **CI Security Auditing**: GitHub Actions workflow includes mandatory `npm audit --audit-level=high` step.
- **Zero Runtime Overhead**: No third-party runtime npm dependencies (`"dependencies": {}`).
- **Dual Bundle**: Ships CommonJS (`dist/index.js`, `dist/cli.js`) & ESM (`dist/index.mjs`, `dist/cli.mjs`) with TypeScript declaration maps (`dist/index.d.ts`, `dist/cli.d.ts`).
