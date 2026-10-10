import type { DedupeStore } from "./types.js";

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

  async hasOrSet(key: string, ttlMs: number): Promise<boolean> {
    const ttl = String(Math.max(1, Math.round(ttlMs)));
    // "OK" when the key was set (new event), null when it already existed. Anything
    // else counts as new: processing twice beats silently dropping an event.
    const reply = await this.run([
      "SET",
      this.keyPrefix + key,
      "1",
      "PX",
      ttl,
      "NX",
    ]);
    return reply === null;
  }

  async delete(key: string): Promise<void> {
    await this.run(["DEL", this.keyPrefix + key]);
  }
}
