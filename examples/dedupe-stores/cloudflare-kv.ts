/**
 * Distributed DedupeStore backed by Cloudflare Workers KV.
 *
 * This is a reference example, not a bundled dependency — verihook stays at
 * zero runtime dependencies. Copy this file into your project if you are
 * deploying on Cloudflare Workers and using KV for key-value storage.
 *
 * ⚠️ Consistency Warning:
 * Cloudflare KV is eventually consistent across global edge locations (typically
 * replicating globally within 60 seconds). If two identical webhook requests hit
 * different global edge POPs within milliseconds of each other, KV might allow
 * both through before replication completes. For strict zero-race atomic lock
 * guarantees on Cloudflare, consider Cloudflare Durable Objects or Upstash Redis.
 *
 * Setup:
 *   Bind a KV namespace in wrangler.jsonc / wrangler.toml:
 *   [[kv_namespaces]]
 *   binding = "VERIHOOK_DEDUPE_KV"
 *   id = "<your-kv-namespace-id>"
 *
 * Usage:
 *   import { verifyWebhook } from 'verihook';
 *   import { CloudflareKVDedupeStore } from './cloudflare-kv';
 *
 *   const dedupeStore = new CloudflareKVDedupeStore(env.VERIHOOK_DEDUPE_KV);
 *   const result = await verifyWebhook('stripe', req, secret, { dedupeStore });
 */

import type { DedupeStore } from "verihook";

export interface KVNamespaceLike {
  get(key: string): Promise<string | null>;
  put(
    key: string,
    value: string,
    options?: { expirationTtl?: number },
  ): Promise<void>;
}

export class CloudflareKVDedupeStore implements DedupeStore {
  private kv: KVNamespaceLike;
  private keyPrefix: string;

  constructor(kvNamespace: KVNamespaceLike, options?: { keyPrefix?: string }) {
    this.kv = kvNamespace;
    this.keyPrefix = options?.keyPrefix ?? "verihook:dedupe:";
  }

  async hasOrSet(key: string, ttlMs: number): Promise<boolean> {
    const fullKey = this.keyPrefix + key;
    const existing = await this.kv.get(fullKey);

    if (existing !== null) {
      return true; // Key exists -> duplicate event
    }

    // Convert TTL to seconds (minimum 60s for Cloudflare KV expirationTtl)
    const expirationTtl = Math.max(60, Math.ceil(ttlMs / 1000));
    await this.kv.put(fullKey, "1", { expirationTtl });

    return false; // First time seeing event
  }
}
