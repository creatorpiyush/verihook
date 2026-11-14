import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { computeHmacSha256 } from "../src/core/crypto.js";
import {
  createWebhookHandler,
  MemoryDedupeStore,
  RedisDedupeStore,
  verifyWebhook,
  verihookExpress,
  type DedupeStore,
} from "../src/index.js";
import { createWebhookHandler as createLambdaHandler } from "../src/lambda.js";
import { settleDedupeOnFinish } from "../src/middleware/shared.js";
import { bytesToHex } from "../src/utils/encoding.js";

const secret = "razorpay_secret";
const body = JSON.stringify({ id: "evt_two_phase_1" });
const key = "razorpay:evt_two_phase_1";

async function signedHeaders() {
  return {
    "x-razorpay-signature": bytesToHex(await computeHmacSha256(secret, body)),
  };
}

async function makeReq() {
  return new Request("http://localhost/webhooks/razorpay", {
    method: "POST",
    headers: await signedHeaders(),
    body,
  });
}

function mockRes() {
  const listeners: Record<string, () => void> = {};
  const res: any = { statusCode: 200 };
  res.status = vi.fn((code: number) => {
    res.statusCode = code;
    return res;
  });
  res.json = vi.fn((data: unknown) => {
    res.body = data;
    return res;
  });
  res.setHeader = vi.fn();
  res.on = vi.fn((event: string, cb: () => void) => {
    listeners[event] = cb;
  });
  res.emit = (event: string) => listeners[event]?.();
  return res;
}

beforeEach(() => {
  vi.useFakeTimers();
});
afterEach(() => {
  vi.useRealTimers();
});

describe("MemoryDedupeStore claim / commit", () => {
  it("reports new, then processing, then done after commit", () => {
    const store = new MemoryDedupeStore();
    expect(store.claim("a", 60_000, "t1")).toBe("new");
    expect(store.claim("a", 60_000, "t2")).toBe("processing");
    store.commit("a", 3_600_000, "t1");
    expect(store.claim("a", 60_000, "t3")).toBe("done");
    expect(store.hasOrSet("a")).toBe(true);
  });

  it("lets an uncommitted claim expire after the processing TTL", () => {
    const store = new MemoryDedupeStore();
    store.claim("a", 60_000, "t1");
    vi.advanceTimersByTime(60_001);
    expect(store.claim("a", 60_000, "t2")).toBe("new");
  });

  it("keeps a committed key for the full TTL", () => {
    const store = new MemoryDedupeStore();
    store.claim("a", 60_000, "t1");
    store.commit("a", 3_600_000, "t1");
    vi.advanceTimersByTime(3_599_000);
    expect(store.claim("a", 60_000, "t2")).toBe("done");
    vi.advanceTimersByTime(2_000);
    expect(store.claim("a", 60_000, "t3")).toBe("new");
  });

  it("ignores commit and delete from a delivery whose claim was taken over", () => {
    const store = new MemoryDedupeStore();
    store.claim("a", 60_000, "stale");
    vi.advanceTimersByTime(60_001);
    store.claim("a", 60_000, "fresh");

    store.delete("a", "stale");
    expect(store.claim("a", 60_000, "x")).toBe("processing");
    store.commit("a", 3_600_000, "stale");
    expect(store.claim("a", 60_000, "x")).toBe("processing");

    store.commit("a", 3_600_000, "fresh");
    expect(store.claim("a", 60_000, "x")).toBe("done");
    store.delete("a", "stale");
    store.delete("a", "fresh");
    expect(store.claim("a", 60_000, "x")).toBe("done");
  });

  it("records a commit whose claim was evicted or expired", () => {
    const store = new MemoryDedupeStore();
    store.claim("a", 60_000, "t1");
    vi.advanceTimersByTime(60_001);
    store.commit("a", 3_600_000, "t1");
    expect(store.claim("a", 60_000, "t2")).toBe("done");
  });

  it("keeps commits within maxSize", () => {
    const store = new MemoryDedupeStore({ maxSize: 2 });
    store.claim("a", 60_000, "ta");
    store.claim("b", 60_000, "tb");
    store.claim("c", 60_000, "tc"); // evicts "a"
    store.commit("a", 3_600_000, "ta"); // re-inserted, evicts "b"
    expect(store.size).toBe(2);
  });
});

describe("verifyWebhook with dedupeProcessingTtlMs", () => {
  it("fails a delivery that arrives during processing with EVENT_IN_PROGRESS", async () => {
    const options = {
      dedupeStore: new MemoryDedupeStore(),
      dedupeProcessingTtlMs: 60_000,
    };
    const req = { headers: await signedHeaders(), body };

    const first = await verifyWebhook("razorpay", req, secret, options);
    expect(first.valid).toBe(true);
    expect(first.dedupeKey).toBe(key);
    expect(first.dedupeToken).toMatch(/^[0-9a-f]{32}$/);

    const second = await verifyWebhook("razorpay", req, secret, options);
    expect(second.valid).toBe(false);
    expect(second.code).toBe("EVENT_IN_PROGRESS");

    options.dedupeStore.commit(key, 3_600_000, first.dedupeToken);
    const third = await verifyWebhook("razorpay", req, secret, options);
    expect(third.code).toBe("DUPLICATE_EVENT");
  });

  it("stays single-phase without the option: the key is held for the full TTL", async () => {
    const options = { dedupeStore: new MemoryDedupeStore() };
    const req = { headers: await signedHeaders(), body };

    await verifyWebhook("razorpay", req, secret, options);
    vi.advanceTimersByTime(3_600_000);
    const second = await verifyWebhook("razorpay", req, secret, options);
    expect(second.code).toBe("DUPLICATE_EVENT");
  });

  it("stays single-phase with a store that has no claim / commit", async () => {
    const seen = new Set<string>();
    const dedupeStore: DedupeStore = {
      hasOrSet: (k) => seen.has(k) || (seen.add(k), false),
    };
    const options = { dedupeStore, dedupeProcessingTtlMs: 60_000 };
    const req = { headers: await signedHeaders(), body };

    await verifyWebhook("razorpay", req, secret, options);
    const second = await verifyWebhook("razorpay", req, secret, options);
    expect(second.code).toBe("DUPLICATE_EVENT");
  });
});

describe("adapters: a crashed handler does not lose the event", () => {
  it("processes the provider's retry once the processing TTL has passed", async () => {
    const dedupeStore = new MemoryDedupeStore();
    const handled = vi.fn();
    let crash = true;
    const handler = createWebhookHandler(
      "razorpay",
      secret,
      () => {
        handled();
        // A killed process never settles: no response, no release.
        if (crash) return new Promise<void>(() => {});
      },
      { dedupeStore },
    );

    void handler(await makeReq());
    await vi.waitFor(() => expect(handled).toHaveBeenCalledTimes(1));

    // A retry while the first delivery may still be running is told to come back.
    const early = await handler(await makeReq());
    expect(early.status).toBe(503);
    expect(await early.json()).toMatchObject({ code: "EVENT_IN_PROGRESS" });
    expect(handled).toHaveBeenCalledTimes(1);

    crash = false;
    vi.advanceTimersByTime(60_001);
    const retry = await handler(await makeReq());
    expect(retry.status).toBe(200);
    expect(await retry.json()).toEqual({ received: true });
    expect(handled).toHaveBeenCalledTimes(2);
  });

  it("keeps a processed event for the full TTL", async () => {
    const dedupeStore = new MemoryDedupeStore();
    const handled = vi.fn();
    const handler = createWebhookHandler("razorpay", secret, handled, {
      dedupeStore,
    });

    expect((await handler(await makeReq())).status).toBe(200);
    vi.advanceTimersByTime(3_600_000);
    const duplicate = await handler(await makeReq());
    expect(await duplicate.json()).toEqual({ received: true, duplicate: true });
    expect(handled).toHaveBeenCalledTimes(1);
  });

  it("dedupeProcessingTtlMs: 0 turns two-phase off in an adapter", async () => {
    const dedupeStore = new MemoryDedupeStore();
    const handler = createWebhookHandler(
      "razorpay",
      secret,
      () => new Promise<void>(() => {}),
      { dedupeStore, dedupeProcessingTtlMs: 0 },
    );

    void handler(await makeReq());
    await vi.waitFor(() => expect(dedupeStore.size).toBe(1));
    const second = await handler(await makeReq());
    expect(await second.json()).toEqual({ received: true, duplicate: true });
  });

  it("Express commits when the response finishes below 500", async () => {
    const dedupeStore = new MemoryDedupeStore();
    const middleware = verihookExpress("razorpay", secret, { dedupeStore });
    const headers = await signedHeaders();

    const ok = mockRes();
    await middleware({ headers, body }, ok, vi.fn());

    const inFlight = mockRes();
    await middleware({ headers, body }, inFlight, vi.fn());
    expect(inFlight.statusCode).toBe(503);
    expect(inFlight.body).toMatchObject({ code: "EVENT_IN_PROGRESS" });

    ok.emit("finish");
    await Promise.resolve();
    vi.advanceTimersByTime(3_600_000);

    const dup = mockRes();
    await middleware({ headers, body }, dup, vi.fn());
    expect(dup.body).toEqual({ received: true, duplicate: true });
  });

  it("Express lets the retry through when the process died mid-request", async () => {
    const dedupeStore = new MemoryDedupeStore();
    const middleware = verihookExpress("razorpay", secret, { dedupeStore });
    const headers = await signedHeaders();

    // No "finish" and no "close": the process was killed.
    await middleware({ headers, body }, mockRes(), vi.fn());
    vi.advanceTimersByTime(60_001);

    const next = vi.fn();
    await middleware({ headers, body }, mockRes(), next);
    expect(next).toHaveBeenCalledWith();
  });
});

describe("RedisDedupeStore claim / commit", () => {
  /** A minimal Redis: SET (with or without NX), GET, DEL and the two EVAL scripts. */
  function fakeRedis() {
    const data = new Map<string, { value: string; expiry: number }>();
    const commands: string[][] = [];
    const read = (k: string) => {
      const entry = data.get(k);
      return entry && entry.expiry > Date.now() ? entry.value : null;
    };
    const call = async (...raw: (string | number)[]): Promise<unknown> => {
      const args = raw.map(String);
      commands.push(args);
      const [cmd, k, value, , ttl, nx] = args;
      if (cmd === "EVAL") {
        const [, script, , evalKey, owner, evalTtl] = args;
        const current = read(evalKey);
        if (script.includes("'DEL'")) {
          return current === owner && data.delete(evalKey) ? 1 : 0;
        }
        if (current !== null && current !== owner) return 0;
        data.set(evalKey, {
          value: "1",
          expiry: Date.now() + Number(evalTtl),
        });
        return "OK";
      }
      if (cmd === "GET") return read(k);
      if (cmd === "DEL") return data.delete(k) ? 1 : 0;
      if (cmd === "SET") {
        if (nx === "NX" && read(k) !== null) return null;
        data.set(k, { value, expiry: Date.now() + Number(ttl) });
        return "OK";
      }
      throw new Error(`unexpected ${cmd}`);
    };
    return { call, commands };
  }

  const k = "verihook:dedupe:stripe:evt_1";

  it("claims with SET NX, reads the state with GET and commits with a fenced EVAL", async () => {
    const redis = fakeRedis();
    const store = new RedisDedupeStore(redis);

    expect(await store.claim("stripe:evt_1", 60_000, "t1")).toBe("new");
    expect(await store.claim("stripe:evt_1", 60_000, "t2")).toBe("processing");
    await store.commit("stripe:evt_1", 3_600_000, "t1");
    expect(await store.claim("stripe:evt_1", 60_000, "t3")).toBe("done");

    expect(redis.commands[0]).toEqual(["SET", k, "p:t1", "PX", "60000", "NX"]);
    expect(redis.commands[2]).toEqual(["GET", k]);
    expect(redis.commands[3]).toEqual([
      "EVAL",
      expect.stringContaining("'SET'"),
      "1",
      k,
      "p:t1",
      "3600000",
    ]);
  });

  it("ignores commit and delete from a delivery whose claim was taken over", async () => {
    const store = new RedisDedupeStore(fakeRedis());
    await store.claim("stripe:evt_1", 60_000, "stale");
    vi.advanceTimersByTime(60_001);
    await store.claim("stripe:evt_1", 60_000, "fresh");

    await store.delete("stripe:evt_1", "stale");
    await store.commit("stripe:evt_1", 3_600_000, "stale");
    expect(await store.claim("stripe:evt_1", 60_000, "x")).toBe("processing");

    await store.commit("stripe:evt_1", 3_600_000, "fresh");
    await store.delete("stripe:evt_1", "fresh");
    expect(await store.claim("stripe:evt_1", 60_000, "x")).toBe("done");
  });

  it("commits and deletes unconditionally without a token", async () => {
    const redis = fakeRedis();
    const store = new RedisDedupeStore(redis);
    await store.commit("stripe:evt_1", 1_000);
    await store.delete("stripe:evt_1");
    expect(redis.commands).toEqual([
      ["SET", k, "1", "PX", "1000"],
      ["DEL", k],
    ]);
  });

  it("treats a key that vanished between SET and GET as in progress", async () => {
    const store = new RedisDedupeStore({ call: async () => null });
    expect(await store.claim("stripe:evt_1", 60_000, "t1")).toBe("processing");
  });

  it("lets a crashed claim expire", async () => {
    const store = new RedisDedupeStore(fakeRedis());
    await store.claim("stripe:evt_1", 60_000, "t1");
    vi.advanceTimersByTime(60_001);
    expect(await store.claim("stripe:evt_1", 60_000, "t2")).toBe("new");
  });
});

describe("settling without a response to watch", () => {
  it("commits right away when the response has no .on (NestJS custom platforms)", async () => {
    const dedupeStore = new MemoryDedupeStore();
    const options = { dedupeStore, dedupeProcessingTtlMs: 60_000 };
    const req = { headers: await signedHeaders(), body };
    const result = await verifyWebhook("razorpay", req, secret, options);

    settleDedupeOnFinish({ statusCode: 200 }, result, options);
    await Promise.resolve();
    vi.advanceTimersByTime(3_600_000);

    const again = await verifyWebhook("razorpay", req, secret, options);
    expect(again.code).toBe("DUPLICATE_EVENT");
  });

  it("warns outside production when a commit fails", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const dedupeStore: DedupeStore = {
        hasOrSet: () => false,
        claim: () => "new",
        commit: () => {
          throw new Error("redis down");
        },
      };
      const handler = createWebhookHandler("razorpay", secret, () => {}, {
        dedupeStore,
      });
      expect((await handler(await makeReq())).status).toBe(200);
      expect(warn).toHaveBeenCalledWith(
        `[verihook] dedupeStore commit failed for "${key}":`,
        expect.any(Error),
      );
    } finally {
      warn.mockRestore();
    }
  });
});

describe("Lambda adapter claim TTL", () => {
  function lambdaEvent(headers: Record<string, string>) {
    return {
      rawPath: "/webhooks/razorpay",
      headers,
      body,
      requestContext: { domainName: "x.on.aws", http: { method: "POST" } },
    };
  }

  it("holds the claim for the invocation's remaining time when longer than 60 s", async () => {
    const claim = vi.fn(() => "new" as const);
    const dedupeStore: DedupeStore = {
      hasOrSet: () => false,
      claim,
      commit: () => {},
    };
    const lambda = createLambdaHandler("razorpay", secret, () => {}, {
      dedupeStore,
    });
    const context = { getRemainingTimeInMillis: () => 900_000 };

    await lambda(lambdaEvent(await signedHeaders()), context);
    expect(claim).toHaveBeenCalledWith(key, 901_000, expect.any(String));
  });

  it("keeps the 60 s default for short invocations and an explicit TTL as given", async () => {
    const claim = vi.fn(() => "new" as const);
    const dedupeStore: DedupeStore = {
      hasOrSet: () => false,
      claim,
      commit: () => {},
    };
    const context = { getRemainingTimeInMillis: () => 3_000 };
    const headers = await signedHeaders();

    await createLambdaHandler("razorpay", secret, () => {}, { dedupeStore })(
      lambdaEvent(headers),
      context,
    );
    expect(claim).toHaveBeenLastCalledWith(key, 60_000, expect.any(String));

    await createLambdaHandler("razorpay", secret, () => {}, {
      dedupeStore,
      dedupeProcessingTtlMs: 5_000,
    })(lambdaEvent(headers), { getRemainingTimeInMillis: () => 900_000 });
    expect(claim).toHaveBeenLastCalledWith(key, 5_000, expect.any(String));
  });
});
