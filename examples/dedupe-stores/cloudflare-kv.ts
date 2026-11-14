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
  delete(key: string): Promise<void>;
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

  /**
   * Lets the verihook adapters release the key when your handler fails, so the
   * provider's retry is processed instead of being acked as a duplicate.
   */
  /**
   * With `token`, deletes only while the key is still claimed by that
   * delivery (checked with a read first, so not atomic).
   */
  async delete(key: string, token?: string): Promise<void> {
    const fullKey = this.keyPrefix + key;
    if (token !== undefined && (await this.kv.get(fullKey)) !== `p:${token}`) {
      return;
    }
    await this.kv.delete(fullKey);
  }

  /**
   * Two-phase recording: a new key is held as in progress (`p:<token>`) for a
   * short time, so a handler that crashes before `commit` doesn't leave a
   * record that drops the provider's retry. Like `hasOrSet`, the get-then-put
   * is not atomic, and KV's minimum TTL is 60 seconds.
   */
  async claim(
    key: string,
    processingTtlMs: number,
    token: string,
  ): Promise<"new" | "processing" | "done"> {
    const fullKey = this.keyPrefix + key;
    const existing = await this.kv.get(fullKey);
    if (existing !== null) return existing === "1" ? "done" : "processing";

    const expirationTtl = Math.max(60, Math.ceil(processingTtlMs / 1000));
    await this.kv.put(fullKey, `p:${token}`, { expirationTtl });
    return "new";
  }

  /**
   * Marks a claimed key as processed and keeps it for `ttlMs`. With `token`,
   * skipped when another delivery has claimed or committed the key (checked
   * with a read first, so not atomic).
   */
  async commit(key: string, ttlMs: number, token?: string): Promise<void> {
    const fullKey = this.keyPrefix + key;
    if (token !== undefined) {
      const existing = await this.kv.get(fullKey);
      if (existing !== null && existing !== `p:${token}`) return;
    }
    const expirationTtl = Math.max(60, Math.ceil(ttlMs / 1000));
    await this.kv.put(fullKey, "1", { expirationTtl });
  }
}
