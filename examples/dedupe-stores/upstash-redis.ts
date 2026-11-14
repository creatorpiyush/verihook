/**
 * Distributed DedupeStore backed by Upstash Redis.
 *
 * Unlike traditional Redis clients (ioredis, node-redis), Upstash's SDK talks
 * to Redis over HTTP/REST, which means it works in edge runtimes that don't
 * support raw TCP sockets (Cloudflare Workers, Vercel Edge Functions, Deno
 * Deploy) in addition to standard Node.js servers.
 *
 * This is a reference example, not a bundled dependency — verihook stays at
 * zero runtime dependencies. Copy this file into your project and install
 * `@upstash/redis` yourself.
 *
 * Setup:
 *   npm install @upstash/redis
 *   Set UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN in your environment
 *   (available from the Upstash console for any Redis database you create).
 *
 * Usage:
 *   import { verifyWebhook } from 'verihook';
 *   import { UpstashDedupeStore } from './upstash-redis';
 *
 *   const dedupeStore = new UpstashDedupeStore();
 *
 *   const result = await verifyWebhook('stripe', req, secret, { dedupeStore });
 */

import { Redis } from "@upstash/redis";
import type { DedupeStore } from "verihook";

/** Commit unless another delivery claimed or committed the key (a missing key is recorded). */
const COMMIT_SCRIPT = `local v = redis.call('GET', KEYS[1])
if v == false or v == ARGV[1] then
  return redis.call('SET', KEYS[1], '1', 'PX', ARGV[2])
end
return 0`;

/** Delete only while the key is still claimed by this delivery. */
const RELEASE_SCRIPT = `if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
end
return 0`;

export class UpstashDedupeStore implements DedupeStore {
  private redis: Redis;
  private keyPrefix: string;

  constructor(options?: { redis?: Redis; keyPrefix?: string }) {
    // Redis.fromEnv() reads UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN
    this.redis = options?.redis ?? Redis.fromEnv();
    this.keyPrefix = options?.keyPrefix ?? "verihook:dedupe:";
  }

  /**
   * Atomically checks-and-sets using Redis SET ... NX PX, which is atomic
   * even under concurrent requests hitting different serverless/edge
   * instances simultaneously — the property MemoryDedupeStore cannot offer
   * across more than one instance.
   */
  async hasOrSet(key: string, ttlMs: number): Promise<boolean> {
    const fullKey = this.keyPrefix + key;

    // SET key value NX PX ttlMs
    // Returns "OK" if the key was newly set (not a duplicate).
    // Returns null if the key already existed (duplicate event).
    const setResult = await this.redis.set(fullKey, "1", {
      nx: true,
      px: Math.max(1, Math.round(ttlMs)),
    });

    return setResult === null;
  }

  /**
   * Lets the verihook adapters release the key when your handler fails, so the
   * provider's retry is processed instead of being acked as a duplicate. With
   * `token`, only while the key is still claimed by that delivery.
   */
  async delete(key: string, token?: string): Promise<void> {
    const fullKey = this.keyPrefix + key;
    if (token === undefined) {
      await this.redis.del(fullKey);
      return;
    }
    await this.redis.eval(RELEASE_SCRIPT, [fullKey], [`p:${token}`]);
  }

  /**
   * Two-phase recording: a new key is held as in progress ("p") for a short
   * time, so a handler that crashes before `commit` doesn't leave a record
   * that drops the provider's retry.
   */
  async claim(
    key: string,
    processingTtlMs: number,
    token: string,
  ): Promise<"new" | "processing" | "done"> {
    const fullKey = this.keyPrefix + key;
    const setResult = await this.redis.set(fullKey, `p:${token}`, {
      nx: true,
      px: Math.max(1, Math.round(processingTtlMs)),
    });
    if (setResult !== null) return "new";
    // A key that expired between the two commands reads as in progress, so the
    // provider is asked to retry.
    return String(await this.redis.get(fullKey)) === "1"
      ? "done"
      : "processing";
  }

  /**
   * Marks a claimed key as processed and keeps it for `ttlMs`. With `token`,
   * atomically skipped when another delivery has claimed or committed it.
   */
  async commit(key: string, ttlMs: number, token?: string): Promise<void> {
    const fullKey = this.keyPrefix + key;
    const px = Math.max(1, Math.round(ttlMs));
    if (token === undefined) {
      await this.redis.set(fullKey, "1", { px });
      return;
    }
    await this.redis.eval(COMMIT_SCRIPT, [fullKey], [`p:${token}`, String(px)]);
  }

  async clear(): Promise<void> {
    // Best-effort helper for tests/dev — scans and deletes keys under the
    // prefix. Avoid calling this in production against a shared database.
    let cursor = 0;
    do {
      const [nextCursor, keys] = await this.redis.scan(cursor, {
        match: `${this.keyPrefix}*`,
        count: 100,
      });
      cursor = Number(nextCursor);
      if (keys.length > 0) {
        await this.redis.del(...keys);
      }
    } while (cursor !== 0);
  }
}
