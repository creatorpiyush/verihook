import type { DedupeClaim, DedupeStore } from "./types.js";

/** ioredis: `redis.call("SET", ...)`. */
interface IORedisLike {
  call(command: string, ...args: (string | number)[]): Promise<unknown>;
}

/** node-redis v4/v5: `client.sendCommand(["SET", ...])`. */
interface NodeRedisLike {
  sendCommand(args: string[]): Promise<unknown>;
}

/** Bun's built-in `RedisClient`: `redis.send("SET", [...])`. */
interface BunRedisLike {
  send(command: string, args: string[]): Promise<unknown>;
}

/** A connected ioredis, node-redis (v4+) or Bun `RedisClient` instance. */
export type RedisClientLike = IORedisLike | NodeRedisLike | BunRedisLike;

export interface RedisDedupeStoreOptions {
  /**
   * Prefix added to every key.
   * @default "verihook:dedupe:"
   */
  keyPrefix?: string;
}

/**
 * A `DedupeStore` shared by every instance through Redis, using your own client
 * (ioredis, node-redis v4+ or Bun's `RedisClient`). verihook adds no dependency.
 *
 * `hasOrSet` is an atomic `SET key 1 PX <ttl> NX`, so two instances receiving the
 * same delivery at once can't both process it. `delete` lets the adapters release
 * a key when your handler fails. Redis errors are not swallowed: verification
 * fails and the provider retries.
 *
 * ```ts
 * import Redis from 'ioredis';
 * const dedupeStore = new RedisDedupeStore(new Redis(process.env.REDIS_URL!));
 * ```
 */
export class RedisDedupeStore implements DedupeStore {
  private readonly run: (args: string[]) => Promise<unknown>;
  private readonly keyPrefix: string;

  constructor(client: RedisClientLike, options?: RedisDedupeStoreOptions) {
    // ioredis also has a `sendCommand`, but it takes a Command object: check `call` first.
    if (typeof (client as IORedisLike).call === "function") {
      const c = client as IORedisLike;
      this.run = ([command, ...args]) => c.call(command, ...args);
    } else if (typeof (client as NodeRedisLike).sendCommand === "function") {
      const c = client as NodeRedisLike;
      this.run = (args) => c.sendCommand(args);
    } else if (typeof (client as BunRedisLike).send === "function") {
      const c = client as BunRedisLike;
      this.run = ([command, ...args]) => c.send(command, args);
    } else {
      throw new TypeError(
        "[verihook] RedisDedupeStore needs an ioredis, node-redis (v4+) or Bun RedisClient instance",
      );
    }
    this.keyPrefix = options?.keyPrefix ?? "verihook:dedupe:";
  }

  /**
   * `SET key <value> PX <ttl> NX`: true when the key was set. Redis replies "OK"
   * for a new key and null for an existing one. Anything else counts as new:
   * processing twice beats silently dropping an event.
   */
  private async setIfAbsent(
    key: string,
    value: string,
    ttlMs: number,
  ): Promise<boolean> {
    const reply = await this.run([
      "SET",
      this.keyPrefix + key,
      value,
      "PX",
      String(Math.max(1, Math.round(ttlMs))),
      "NX",
    ]);
    return reply !== null;
  }

  async hasOrSet(key: string, ttlMs: number): Promise<boolean> {
    return !(await this.setIfAbsent(key, "1", ttlMs));
  }

  /**
   * Records a new key as in progress (`p:<token>`) for `processingTtlMs`. Two
   * round trips only when the key exists (a retry): `SET ... NX GET` would do it
   * in one, but needs Redis 7.
   */
  async claim(
    key: string,
    processingTtlMs: number,
    token: string,
  ): Promise<DedupeClaim> {
    if (await this.setIfAbsent(key, `p:${token}`, processingTtlMs)) {
      return "new";
    }
    // A key that expired or was released between the two commands reads as in
    // progress, so the provider is asked to retry rather than told it is done.
    const value = await this.run(["GET", this.keyPrefix + key]);
    return String(value) === "1" ? "done" : "processing";
  }

  /**
   * Marks a claimed key as processed (`1`) and keeps it for `ttlMs`. With
   * `token`, atomically skipped when another delivery owns the key.
   */
  async commit(key: string, ttlMs: number, token?: string): Promise<void> {
    const ttl = String(Math.max(1, Math.round(ttlMs)));
    const fullKey = this.keyPrefix + key;
    if (token === undefined) {
      await this.run(["SET", fullKey, "1", "PX", ttl]);
      return;
    }
    await this.run(["EVAL", COMMIT_SCRIPT, "1", fullKey, `p:${token}`, ttl]);
  }

  /**
   * Deletes the key. With `token`, atomically only while it is still claimed
   * with that token.
   */
  async delete(key: string, token?: string): Promise<void> {
    const fullKey = this.keyPrefix + key;
    if (token === undefined) {
      await this.run(["DEL", fullKey]);
      return;
    }
    await this.run(["EVAL", RELEASE_SCRIPT, "1", fullKey, `p:${token}`]);
  }
}

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
