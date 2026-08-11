# verihook Reference Dedupe Stores

This directory contains reference implementations for distributed **`DedupeStore`** backends.

`verihook` includes an in-memory deduplication store (`MemoryDedupeStore`) out of the box. However, multi-instance production deployments, serverless functions, and edge runtimes (such as Vercel, Cloudflare Workers, or AWS Lambda) require a central or distributed store to prevent replay attacks and duplicate webhook event processing across instance boundaries.

---

## ⚡ Zero-Dependency Architecture

To keep `verihook` lightweight and free of transitive dependencies, these stores are **reference implementations** rather than bundled library dependencies.

- You can copy the store file directly into your application codebase.
- Install the required client package in your own application project as needed.

---

## 🚀 Getting Started

This example directory is configured as a standalone Node.js ES module project.

```bash
cd examples/dedupe-stores
npm install
npm run typecheck
```

---

## 📦 Available Stores

### 1. Upstash Redis ([`upstash-redis.ts`](./upstash-redis.ts))

- **Best for**: Serverless & Edge environments (Vercel Edge, Cloudflare Workers, Next.js, AWS Lambda) or standard Node.js applications.
- **Protocol**: HTTP / REST (works without raw TCP sockets).
- **Guarantees**: Atomic `SET ... NX PX` locks under high concurrency.
- **Setup in your project**:
  ```bash
  npm install @upstash/redis
  ```
  Set `UPSTASH_REDIS_REST_URL` and `UPSTASH_REDIS_REST_TOKEN` in your environment.

---

### 2. Cloudflare Workers KV ([`cloudflare-kv.ts`](./cloudflare-kv.ts))

- **Best for**: Cloudflare Workers and Pages Functions.
- **Protocol**: Cloudflare Workers native KV binding.
- **Guarantees**: Global key-value cache (eventually consistent).
- **Setup in your project**:
  Bind a KV namespace in your `wrangler.jsonc` or `wrangler.toml`:
  ```toml
  [[kv_namespaces]]
  binding = "VERIHOOK_DEDUPE_KV"
  id = "<your-kv-namespace-id>"
  ```
- **Dependencies**: None. Uses structural type interface `KVNamespaceLike`.

---

## 🚀 Basic Usage

```typescript
import { verifyWebhook } from "verihook";
import { UpstashDedupeStore } from "./dedupe-stores/upstash-redis";
// OR
// import { CloudflareKVDedupeStore } from "./dedupe-stores/cloudflare-kv";

const dedupeStore = new UpstashDedupeStore();

const result = await verifyWebhook(provider, request, secret, {
  dedupeStore,
  ttlMs: 300_000, // 5 minutes (default)
});

if (result.isDuplicate) {
  // Webhook payload was already processed
  return new Response("Duplicate webhook event ignored", { status: 200 });
}
```

---

## 🛠️ Implementing a Custom Store

Any object that implements the simple `DedupeStore` interface can be passed into `verifyWebhook`:

```typescript
import type { DedupeStore } from "verihook";

export class CustomDedupeStore implements DedupeStore {
  /**
   * Checks if `key` exists and is active.
   * If present and valid, returns `true` (duplicate event).
   * If missing, sets `key` with TTL and returns `false` (new event).
   */
  async hasOrSet(key: string, ttlMs: number): Promise<boolean> {
    // Implement your check-and-set logic here
  }

  /**
   * Optional helper to clear keys.
   */
  async clear?(): Promise<void>;
}
```
