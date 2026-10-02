import { describe, expect, it, vi } from "vitest";
import { computeHmacSha256 } from "../src/core/crypto.js";
import {
  createWebhookHandler,
  MemoryDedupeStore,
  verifyWebhook,
  verihookExpress,
} from "../src/index.js";
import { bytesToHex } from "../src/utils/encoding.js";

const secret = "razorpay_secret";
const body = JSON.stringify({ id: "evt_retry_1" });

async function signedHeaders() {
  return {
    "x-razorpay-signature": bytesToHex(await computeHmacSha256(secret, body)),
  };
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

describe("MemoryDedupeStore bounds", () => {
  it("caps size at 10,000 entries by default", () => {
    const store = new MemoryDedupeStore();
    for (let i = 0; i < 10_050; i++) store.hasOrSet(`k${i}`);
    expect(store.size).toBe(10_000);
  });

  it("drops expired entries on insert", () => {
    vi.useFakeTimers();
    try {
      const store = new MemoryDedupeStore({ ttlMs: 1_000 });
      store.hasOrSet("a");
      store.hasOrSet("b");
      vi.advanceTimersByTime(1_500);
      store.hasOrSet("c");
      expect(store.size).toBe(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it("delete() allows the key to be recorded again", () => {
    const store = new MemoryDedupeStore();
    expect(store.hasOrSet("a")).toBe(false);
    store.delete("a");
    expect(store.hasOrSet("a")).toBe(false);
  });
});

describe("dedupe retry semantics", () => {
  it("exposes dedupeKey on a verified result", async () => {
    const result = await verifyWebhook(
      "razorpay",
      { headers: await signedHeaders(), body },
      secret,
      { dedupeStore: new MemoryDedupeStore() },
    );
    expect(result.dedupeKey).toBe("razorpay:evt_retry_1");
  });

  it("Express acknowledges duplicates with 200 instead of 401", async () => {
    const dedupeStore = new MemoryDedupeStore();
    const middleware = verihookExpress("razorpay", secret, { dedupeStore });
    const headers = await signedHeaders();

    await middleware({ headers, body }, mockRes(), vi.fn());
    const res = mockRes();
    const next = vi.fn();
    await middleware({ headers, body }, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual({ received: true, duplicate: true });
  });

  it("Express releases the event when the response finishes with 5xx", async () => {
    const dedupeStore = new MemoryDedupeStore();
    const middleware = verihookExpress("razorpay", secret, { dedupeStore });
    const headers = await signedHeaders();

    const failed = mockRes();
    await middleware({ headers, body }, failed, vi.fn());
    failed.statusCode = 500;
    failed.emit("finish");
    await Promise.resolve();

    const retry = mockRes();
    const next = vi.fn();
    await middleware({ headers, body }, retry, next);
    expect(next).toHaveBeenCalledWith();
  });

  it("Next.js handler acknowledges duplicates and releases on handler failure", async () => {
    const dedupeStore = new MemoryDedupeStore();
    const headers = await signedHeaders();
    const makeReq = () =>
      new Request("http://localhost/webhooks/razorpay", {
        method: "POST",
        headers,
        body,
      });

    let shouldFail = true;
    const handler = createWebhookHandler(
      "razorpay",
      secret,
      async () => {
        if (shouldFail) throw new Error("db down");
      },
      { dedupeStore },
    );

    expect((await handler(makeReq())).status).toBe(500);

    shouldFail = false;
    const retry = await handler(makeReq());
    expect(retry.status).toBe(200);
    expect(await retry.json()).toEqual({ received: true });

    const duplicate = await handler(makeReq());
    expect(duplicate.status).toBe(200);
    expect(await duplicate.json()).toEqual({ received: true, duplicate: true });
  });
});
