import { describe, expect, it } from "vitest";
import { createWebhookHandler } from "../src/next.js";
import { RedisDedupeStore, verifyWebhook } from "../src/index.js";
import { signWebhook } from "../src/testing.js";

/**
 * A minimal Redis: SET ... PX ... [NX], GET, DEL, and EVAL of the two
 * check-and-act scripts, recording every command.
 */
function fakeRedis() {
  const data = new Map<string, { value: string; expiry: number }>();
  const commands: string[][] = [];
  const exec = async (args: (string | number)[]): Promise<unknown> => {
    const [cmd, key, value, , ttl, nx] = args.map(String);
    commands.push(args.map(String));
    if (cmd === "EVAL") {
      const [, script, , k, owner, evalTtl] = args.map(String);
      const entry = data.get(k);
      const current = entry && entry.expiry > Date.now() ? entry.value : null;
      if (script.includes("'DEL'")) {
        return current === owner && data.delete(k) ? 1 : 0;
      }
      if (current !== null && current !== owner) return 0;
      data.set(k, { value: "1", expiry: Date.now() + Number(evalTtl) });
      return "OK";
    }
    const live = (data.get(key)?.expiry ?? 0) > Date.now();
    if (cmd === "SET") {
      if (nx === "NX" && live) return null;
      data.set(key, { value, expiry: Date.now() + Number(ttl) });
      return "OK";
    }
    if (cmd === "GET") return live ? data.get(key)!.value : null;
    if (cmd === "DEL") return data.delete(key) ? 1 : 0;
    throw new Error(`unexpected ${cmd}`);
  };
  return { exec, commands };
}

const clients = {
  ioredis: (r: ReturnType<typeof fakeRedis>) => ({
    call: (c: string, ...a: (string | number)[]) => r.exec([c, ...a]),
    // ioredis' own sendCommand takes a Command object; it must not be used.
    sendCommand: () => {
      throw new Error("wrong method");
    },
  }),
  "node-redis": (r: ReturnType<typeof fakeRedis>) => ({
    sendCommand: (a: string[]) => r.exec(a),
  }),
  bun: (r: ReturnType<typeof fakeRedis>) => ({
    send: (c: string, a: string[]) => r.exec([c, ...a]),
  }),
};

describe.each(Object.entries(clients))(
  "RedisDedupeStore with %s",
  (_, make) => {
    it("sends an atomic SET NX PX and reports duplicates", async () => {
      const redis = fakeRedis();
      const store = new RedisDedupeStore(make(redis));
      expect(await store.hasOrSet("stripe:evt_1", 60_000)).toBe(false);
      expect(await store.hasOrSet("stripe:evt_1", 60_000)).toBe(true);
      expect(redis.commands[0]).toEqual([
        "SET",
        "verihook:dedupe:stripe:evt_1",
        "1",
        "PX",
        "60000",
        "NX",
      ]);
    });

    it("delete releases the key; keyPrefix is applied", async () => {
      const redis = fakeRedis();
      const store = new RedisDedupeStore(make(redis), { keyPrefix: "app:" });
      await store.hasOrSet("k", 1000);
      await store.delete("k");
      expect(redis.commands[1]).toEqual(["DEL", "app:k"]);
      expect(await store.hasOrSet("k", 1000)).toBe(false);
    });
  },
);

describe("RedisDedupeStore", () => {
  it("rejects objects that aren't a supported client", () => {
    expect(() => new RedisDedupeStore({} as never)).toThrow(/ioredis/);
  });

  it("treats only a nil reply as a duplicate", async () => {
    const store = new RedisDedupeStore({ sendCommand: async () => undefined });
    expect(await store.hasOrSet("k", 1000)).toBe(false);
  });

  it("fails verification (not silently passes) when Redis is down", async () => {
    const store = new RedisDedupeStore({
      sendCommand: async () => {
        throw new Error("ECONNREFUSED");
      },
    });
    const signed = await signWebhook("stripe", {
      payload: { id: "evt_down" },
      secret: "whsec_x",
    });
    const result = await verifyWebhook("stripe", signed, "whsec_x", {
      dedupeStore: store,
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("ECONNREFUSED");
  });

  it("an adapter releases the key when the handler fails, so the retry is processed", async () => {
    const store = new RedisDedupeStore(clients["node-redis"](fakeRedis()));
    let fail = true;
    const handler = createWebhookHandler(
      "stripe",
      "whsec_x",
      () => {
        if (fail) throw new Error("db down");
      },
      { dedupeStore: store },
    );
    const signed = await signWebhook("stripe", {
      payload: { id: "evt_retry" },
      secret: "whsec_x",
    });
    const send = () =>
      handler(
        new Request(signed.url, {
          method: "POST",
          headers: signed.headers,
          body: signed.body,
        }),
      );
    expect((await send()).status).toBe(500);
    fail = false;
    expect((await send()).status).toBe(200);
    expect(await (await send()).json()).toEqual({
      received: true,
      duplicate: true,
    });
  });
});
