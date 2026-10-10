/**
 * Shared dedupe store on your own Redis (TCP), with the built-in RedisDedupeStore.
 * Works with ioredis, node-redis v4+ and Bun's RedisClient. For edge runtimes
 * without TCP, use the Upstash example (HTTP) instead.
 *
 * Setup:
 *   npm install ioredis   # or: npm install redis
 *   Set REDIS_URL in your environment.
 */

import { Redis } from "ioredis";
import { createClient } from "redis";
import { RedisDedupeStore, verifyWebhook } from "verihook";

// ioredis
export const ioredisStore = new RedisDedupeStore(
  new Redis(process.env.REDIS_URL ?? "redis://localhost:6379"),
);

// node-redis: connect before the first webhook arrives.
export async function nodeRedisStore(): Promise<RedisDedupeStore> {
  const client = await createClient({ url: process.env.REDIS_URL }).connect();
  return new RedisDedupeStore(client, { keyPrefix: "myapp:webhooks:" });
}

export async function handle(request: Request): Promise<Response> {
  const result = await verifyWebhook(
    "stripe",
    request,
    process.env.STRIPE_WEBHOOK_SECRET!,
    { dedupeStore: ioredisStore },
  );
  if (!result.valid) {
    return new Response(result.reason, { status: 401 });
  }
  return Response.json({ received: true });
}
