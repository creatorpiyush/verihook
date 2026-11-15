import { afterEach, describe, expect, it, vi } from "vitest";
import {
  extractEventId,
  MemoryDedupeStore,
  providers,
  verifyMercadoPago,
  verifyWebhook,
} from "../src/index.js";
import { computeHmacSha256 } from "../src/core/crypto.js";
import { bytesToHex } from "../src/utils/encoding.js";
import { signWebhook } from "../src/testing.js";

// Values from the official SDK's spec (mercadopago/sdk-nodejs,
// src/utils/webhook/webhook.spec.ts). Digests computed independently with
// node:crypto over the documented manifest.
const SDK = {
  secret: "your_secret_key_here",
  requestId: "2066ca19-c6f1-498a-be75-1923005edd06",
  ts: "1742505638683", // 13 digits, as in the SDK fixture
  lower: {
    dataId: "ord01jq4s4ky8hwq6na5pxb65b3d3",
    v1: "633f91233312dd391ec75fa0bea539cfc2d6c4918873305b84a96cc1c58db71c",
  },
  upper: {
    dataId: "ORD01JQ4S4KY8HWQ6NA5PXB65B3D3",
    v1: "fb15ae6472eb449173c556793205d77787d58f384d183bb5bc3b724c27bd103c",
  },
};

const SECRET = "mp_test_secret";
const NOW = 1_742_505_638;
const body = JSON.stringify({
  id: 12345,
  action: "payment.created",
  type: "payment",
  data: { id: "123456" },
});

async function signed(opts: {
  dataId?: string;
  requestId?: string;
  ts?: number | string;
  secret?: string;
}) {
  const ts = String(opts.ts ?? NOW);
  let manifest = "";
  if (opts.dataId) manifest += `id:${opts.dataId};`;
  if (opts.requestId) manifest += `request-id:${opts.requestId};`;
  manifest += `ts:${ts};`;
  const v1 = bytesToHex(
    await computeHmacSha256(opts.secret ?? SECRET, manifest),
  );
  const headers: Record<string, string> = {
    "x-signature": `ts=${ts},v1=${v1}`,
  };
  if (opts.requestId) headers["x-request-id"] = opts.requestId;
  const query = opts.dataId
    ? `?data.id=${encodeURIComponent(opts.dataId)}&type=payment`
    : "";
  return { headers, body, url: `https://shop.example/webhooks/mp${query}` };
}

afterEach(() => vi.restoreAllMocks());

describe("Mercado Pago", () => {
  describe("known vectors (official SDK fixture values)", () => {
    for (const [label, v] of Object.entries({
      lowercase: SDK.lower,
      "uppercase (case kept)": SDK.upper,
    })) {
      it(`verifies the ${label} data.id vector`, async () => {
        const result = await verifyMercadoPago(
          {
            headers: {
              "x-signature": `ts=${SDK.ts},v1=${v.v1}`,
              "x-request-id": SDK.requestId,
            },
            body: "{}",
            url: `/webhooks/mp?data.id=${v.dataId}`,
          },
          SDK.secret,
          { now: Number(SDK.ts) },
        );
        expect(result.valid).toBe(true);
        // A millisecond ts is read as seconds for the tolerance check.
        expect(result.timestamp).toBe(1_742_505_638);
      });
    }

    it("doesn't fold the case of data.id", async () => {
      const result = await verifyMercadoPago(
        {
          headers: {
            "x-signature": `ts=${SDK.ts},v1=${SDK.upper.v1}`,
            "x-request-id": SDK.requestId,
          },
          body: "{}",
          url: `/webhooks/mp?data.id=${SDK.lower.dataId}`,
        },
        SDK.secret,
        { now: Number(SDK.ts) },
      );
      expect(result.code).toBe("INVALID_SIGNATURE");
    });
  });

  it("verifies a signed notification and reads action as the event type", async () => {
    const req = await signed({ dataId: "123456", requestId: "req-1" });
    const result = await verifyWebhook("mercadopago", req, SECRET, {
      now: NOW,
    });
    expect(result.valid).toBe(true);
    expect(result.eventType).toBe("payment.created");
    expect(result.timestampVerified).toBe(true);
    expect(result.event).toMatchObject({ data: { id: "123456" } });
  });

  it("falls back to type when there is no action", async () => {
    const req = await signed({ dataId: "1", requestId: "r" });
    const result = await verifyMercadoPago(
      { ...req, body: JSON.stringify({ type: "payment" }) },
      SECRET,
      { now: NOW },
    );
    expect(result.eventType).toBe("payment");
  });

  describe("manifest omission rule", () => {
    it("omits id: when the URL has no data.id", async () => {
      const req = await signed({ requestId: "req-1" });
      expect((await verifyMercadoPago(req, SECRET, { now: NOW })).valid).toBe(
        true,
      );
    });

    it("omits request-id: when there is no x-request-id", async () => {
      const req = await signed({ dataId: "123456" });
      expect((await verifyMercadoPago(req, SECRET, { now: NOW })).valid).toBe(
        true,
      );
    });

    it("signs ts: alone when both are missing", async () => {
      const req = await signed({});
      expect((await verifyMercadoPago(req, SECRET, { now: NOW })).valid).toBe(
        true,
      );
    });

    it("treats blank values as missing", async () => {
      const req = await signed({});
      const result = await verifyMercadoPago(
        {
          ...req,
          headers: { ...req.headers, "x-request-id": "   " },
          url: "/webhooks/mp?data.id=%20",
        },
        SECRET,
        { now: NOW },
      );
      expect(result.valid).toBe(true);
    });
  });

  describe("tampering", () => {
    it("rejects the wrong secret", async () => {
      const req = await signed({ dataId: "123456", requestId: "req-1" });
      const result = await verifyMercadoPago(req, "other", { now: NOW });
      expect(result.code).toBe("INVALID_SIGNATURE");
    });

    it("rejects a changed data.id", async () => {
      const req = await signed({ dataId: "123456", requestId: "req-1" });
      const result = await verifyMercadoPago(
        { ...req, url: req.url.replace("123456", "999999") },
        SECRET,
        { now: NOW },
      );
      expect(result.code).toBe("INVALID_SIGNATURE");
    });

    it("rejects a changed or added x-request-id", async () => {
      const req = await signed({ dataId: "123456", requestId: "req-1" });
      const changed = await verifyMercadoPago(
        { ...req, headers: { ...req.headers, "x-request-id": "req-2" } },
        SECRET,
        { now: NOW },
      );
      expect(changed.code).toBe("INVALID_SIGNATURE");

      const noId = await signed({ dataId: "123456" });
      const added = await verifyMercadoPago(
        { ...noId, headers: { ...noId.headers, "x-request-id": "proxy-id" } },
        SECRET,
        { now: NOW },
      );
      expect(added.code).toBe("INVALID_SIGNATURE");
    });

    it("rejects a data.id dropped from the URL", async () => {
      const req = await signed({ dataId: "123456", requestId: "req-1" });
      const result = await verifyMercadoPago(
        { ...req, url: "https://shop.example/webhooks/mp" },
        SECRET,
        { now: NOW },
      );
      expect(result.code).toBe("INVALID_SIGNATURE");
    });

    it("accepts a changed body: Mercado Pago doesn't sign it", async () => {
      const req = await signed({ dataId: "123456", requestId: "req-1" });
      const result = await verifyMercadoPago(
        { ...req, body: JSON.stringify({ action: "payment.refunded" }) },
        SECRET,
        { now: NOW },
      );
      expect(result.valid).toBe(true);
    });
  });

  describe("headers", () => {
    it.each([
      ["missing", undefined],
      ["garbage", "this-is-garbage"],
      ["no v1", `ts=${NOW}`],
      ["no ts", "v1=abc"],
      ["non-numeric ts", "ts=abc,v1=abc"],
    ])("rejects an x-signature that is %s", async (_label, value) => {
      const headers: Record<string, string> = { "x-request-id": "r" };
      if (value !== undefined) headers["x-signature"] = value;
      const result = await verifyMercadoPago(
        { headers, body, url: "/mp?data.id=1" },
        SECRET,
        { now: NOW },
      );
      expect(result.valid).toBe(false);
      expect(result.code).toBe("MISSING_HEADER");
    });

    it("accepts extra keys and spaces in x-signature", async () => {
      const req = await signed({ dataId: "1", requestId: "r" });
      const [ts, v1] = req.headers["x-signature"].split(",");
      const result = await verifyMercadoPago(
        {
          ...req,
          headers: { ...req.headers, "x-signature": ` ${ts} , v2=zzz, ${v1} ` },
        },
        SECRET,
        { now: NOW },
      );
      expect(result.valid).toBe(true);
    });
  });

  describe("timestamp", () => {
    it("rejects a ts outside the tolerance", async () => {
      const req = await signed({ dataId: "1", requestId: "r", ts: NOW - 301 });
      const result = await verifyMercadoPago(req, SECRET, { now: NOW });
      expect(result.code).toBe("EXPIRED_TIMESTAMP");
    });

    it("accepts a millisecond ts", async () => {
      const req = await signed({
        dataId: "1",
        requestId: "r",
        ts: NOW * 1000 + 683,
      });
      const result = await verifyMercadoPago(req, SECRET, { now: NOW });
      expect(result.valid).toBe(true);
    });

    it("skips the check with tolerance 0", async () => {
      const req = await signed({ dataId: "1", requestId: "r", ts: 1 });
      const result = await verifyMercadoPago(req, SECRET, { tolerance: 0 });
      expect(result.valid).toBe(true);
      expect(result.timestampVerified).toBe(false);
    });
  });

  describe("URL", () => {
    it("fails with MISSING_URL when there is no URL", async () => {
      const req = await signed({ dataId: "1", requestId: "r" });
      const result = await verifyMercadoPago(
        { headers: req.headers, body },
        SECRET,
        { now: NOW },
      );
      expect(result.code).toBe("MISSING_URL");
    });

    it("uses options.url", async () => {
      const req = await signed({ dataId: "1", requestId: "r" });
      const result = await verifyMercadoPago(
        { headers: req.headers, body },
        SECRET,
        { now: NOW, url: req.url },
      );
      expect(result.valid).toBe(true);
    });

    it("reads a relative URL, as Express gives it", async () => {
      const req = await signed({ dataId: "a b+c", requestId: "r" });
      const result = await verifyMercadoPago(
        {
          headers: req.headers,
          body,
          url: `/webhooks/mp?type=payment&data.id=${encodeURIComponent("a b+c")}`,
        },
        SECRET,
        { now: NOW },
      );
      expect(result.valid).toBe(true);
    });
  });

  describe("strict mode", () => {
    it("accepts a signature over data.id and x-request-id", async () => {
      const req = await signed({ dataId: "1", requestId: "r" });
      const result = await verifyMercadoPago(req, SECRET, {
        now: NOW,
        strict: true,
      });
      expect(result.valid).toBe(true);
    });

    it.each([
      ["data.id", { requestId: "r" }, "the data.id query parameter"],
      ["x-request-id", { dataId: "1" }, "the x-request-id header"],
      ["both", {}, "the data.id query parameter and the x-request-id header"],
    ])("rejects a signature without %s", async (_label, opts, missing) => {
      const req = await signed(opts);
      const result = await verifyMercadoPago(req, SECRET, {
        now: NOW,
        strict: true,
      });
      expect(result.code).toBe("WEAK_SCHEME");
      expect(result.reason).toContain(missing);
    });
  });

  describe("dedupe key", () => {
    it("keys on the signed x-request-id, not the unsigned body id", async () => {
      const dedupeStore = new MemoryDedupeStore();
      const req = await signed({ dataId: "123456", requestId: "req-1" });
      const first = await verifyMercadoPago(req, SECRET, {
        now: NOW,
        dedupeStore,
      });
      expect(first.dedupeKey).toBe("mercadopago:req-1");

      // A replay with another body (and body id) is still the same delivery.
      const replay = await verifyMercadoPago(
        { ...req, body: JSON.stringify({ id: 999, action: "x" }) },
        SECRET,
        { now: NOW, dedupeStore },
      );
      expect(replay.code).toBe("DUPLICATE_EVENT");
    });

    it("keys on the signature when there is no x-request-id", async () => {
      const dedupeStore = new MemoryDedupeStore();
      const req = await signed({ dataId: "123456" });
      const first = await verifyMercadoPago(req, SECRET, {
        now: NOW,
        dedupeStore,
      });
      const v1 = req.headers["x-signature"].split("v1=")[1];
      expect(first.dedupeKey).toBe(`mercadopago:sig:${NOW}:${v1}`);
      const replay = await verifyMercadoPago(
        { ...req, body: JSON.stringify({ id: 1 }) },
        SECRET,
        { now: NOW, dedupeStore },
      );
      expect(replay.code).toBe("DUPLICATE_EVENT");
    });

    it("gives a reformatted x-signature the same key (no replay past the store)", async () => {
      const dedupeStore = new MemoryDedupeStore();
      const req = await signed({ dataId: "123456" });
      await verifyMercadoPago(req, SECRET, { now: NOW, dedupeStore });
      const [ts, v1] = req.headers["x-signature"].split(",");
      const reformatted = ` ${v1.toUpperCase().replace("V1=", "v1=")} , v2=zz, ${ts} `;
      const replay = await verifyMercadoPago(
        { ...req, headers: { "x-signature": reformatted } },
        SECRET,
        { now: NOW, dedupeStore },
      );
      expect(replay.code).toBe("DUPLICATE_EVENT");
    });
  });

  describe("extractEventId called directly", () => {
    it("uses the verifier's signed ID when given the verifier", async () => {
      const req = await signed({ dataId: "1", requestId: "req-9" });
      const normalized = {
        headers: req.headers,
        rawBody: JSON.stringify({ id: "unsigned" }),
      };
      expect(
        await extractEventId("mercadopago", normalized, providers.mercadopago),
      ).toBe("req-9");
    });

    it("refuses without the verifier instead of keying on the unsigned body", async () => {
      const req = await signed({ dataId: "1", requestId: "req-9" });
      await expect(
        extractEventId("mercadopago", {
          headers: req.headers,
          rawBody: JSON.stringify({ id: "unsigned" }),
        }),
      ).rejects.toThrow("needs the verifier");
    });
  });

  describe("values that could be read two ways", () => {
    it("rejects a repeated data.id, which frameworks resolve differently", async () => {
      const req = await signed({ dataId: "123456", requestId: "r" });
      for (const extra of ["&data.id=evil", "&data%2Eid=evil"]) {
        const result = await verifyMercadoPago(
          { ...req, url: req.url + extra },
          SECRET,
          { now: NOW },
        );
        expect(result.code).toBe("INVALID_SIGNATURE");
        expect(result.reason).toContain("more than one data.id");
      }
    });

    it("rejects a padded data.id: the app would read a different value", async () => {
      const req = await signed({ dataId: "123456", requestId: "r" });
      const result = await verifyMercadoPago(
        { ...req, url: "/webhooks/mp?data.id=%20123456" },
        SECRET,
        { now: NOW },
      );
      expect(result.reason).toContain("whitespace");
    });

    it("rejects a data.id that smuggles in the request-id pair", async () => {
      // Signed for data.id "1" + x-request-id "X": the manifest
      // "id:1;request-id:X;ts:…;" is also what data.id "1;request-id:X"
      // with no x-request-id would produce.
      const req = await signed({ dataId: "1", requestId: "X" });
      const result = await verifyMercadoPago(
        {
          headers: { "x-signature": req.headers["x-signature"] },
          body,
          url: `/webhooks/mp?data.id=${encodeURIComponent("1;request-id:X")}`,
        },
        SECRET,
        { now: NOW },
      );
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('";" or ":"');
    });

    it("rejects ';' or ':' in x-request-id", async () => {
      const req = await signed({ dataId: "1", requestId: "a;b" });
      const result = await verifyMercadoPago(req, SECRET, { now: NOW });
      expect(result.valid).toBe(false);
    });
  });

  it("warns once outside production that the body isn't signed", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const req = await signed({ dataId: "1", requestId: "r" });
    await verifyMercadoPago(req, SECRET, { now: NOW });
    await verifyMercadoPago(req, SECRET, { now: NOW });
    const hints = warn.mock.calls.filter((c) =>
      String(c[0]).includes("Mercado Pago doesn't sign the body"),
    );
    expect(hints.length).toBeLessThanOrEqual(1);
  });

  describe("signWebhook", () => {
    it("puts data.id and type in the query and signs them", async () => {
      const hook = await signWebhook("mercadopago", {
        secret: SECRET,
        payload: { type: "payment", data: { id: "777" } },
        webhookId: "req-fixed",
      });
      const url = new URL(hook.url);
      expect(url.searchParams.get("data.id")).toBe("777");
      expect(url.searchParams.get("type")).toBe("payment");
      expect(hook.headers["x-request-id"]).toBe("req-fixed");
      const result = await verifyMercadoPago(hook, hook.secret, {
        strict: true,
      });
      expect(result.valid).toBe(true);
    });

    it("keeps a data.id already in the URL and supports a relative URL", async () => {
      const hook = await signWebhook("mercadopago", {
        secret: SECRET,
        payload: { data: { id: "ignored" } },
        url: "/webhooks/mp?data.id=ABC",
      });
      expect(hook.url).toMatch(/^\/webhooks\/mp\?data\.id=ABC/);
      expect((await verifyMercadoPago(hook, SECRET)).valid).toBe(true);
    });

    it("falls back to the body id, then a random one", async () => {
      const fromId = await signWebhook("mercadopago", {
        secret: SECRET,
        payload: { id: 42 },
      });
      expect(new URL(fromId.url).searchParams.get("data.id")).toBe("42");
      const random = await signWebhook("mercadopago", {
        secret: SECRET,
        payload: "not json",
      });
      expect(new URL(random.url).searchParams.get("data.id")).toMatch(
        /^[0-9a-f]{24}$/,
      );
      expect((await verifyMercadoPago(random, SECRET)).valid).toBe(true);
    });
  });
});
