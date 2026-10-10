import { describe, expect, it, vi } from "vitest";
import { verifyWebhook } from "../src/index.js";
import {
  generateWebhookSecret,
  sendWebhook,
  signOutgoingWebhook,
} from "../src/send.js";

const URL_ = "https://hooks.example.com/in";
const payload = { type: "invoice.paid", data: { id: "inv_1" } };

/** A fetch that records the request and answers with `response`. */
function fakeFetch(response: Response | Error) {
  const calls: { url: string; init: RequestInit }[] = [];
  const fn = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(url), init: init! });
    if (response instanceof Error) throw response;
    return response;
  }) as unknown as typeof fetch;
  return { fn, calls };
}

describe("generateWebhookSecret", () => {
  it("returns a whsec_ secret with 32 random bytes", () => {
    const a = generateWebhookSecret();
    expect(a).toMatch(/^whsec_[A-Za-z0-9+/]{43}=$/);
    expect(generateWebhookSecret()).not.toBe(a);
  });
});

describe("signOutgoingWebhook", () => {
  it("is verified by verifyWebhook('standard-webhooks')", async () => {
    const secret = generateWebhookSecret();
    const signed = await signOutgoingWebhook({ secret, payload });
    expect(signed.id).toMatch(/^msg_[0-9a-f]{32}$/);
    const result = await verifyWebhook(
      "standard-webhooks",
      { headers: signed.headers, body: signed.body },
      secret,
    );
    expect(result.valid, result.reason).toBe(true);
    expect(result.event).toEqual(payload);
    expect(result.eventType).toBe("invoice.paid");
  });

  it("signs with every secret during a rotation", async () => {
    const [oldSecret, newSecret] = [
      generateWebhookSecret(),
      generateWebhookSecret(),
    ];
    const signed = await signOutgoingWebhook({
      secret: [newSecret, oldSecret],
      payload,
    });
    expect(signed.headers["webhook-signature"].split(" ")).toHaveLength(2);
    for (const receiverSecret of [oldSecret, newSecret]) {
      const result = await verifyWebhook(
        "standard-webhooks",
        signed,
        receiverSecret,
      );
      expect(result.valid).toBe(true);
    }
  });

  it("keeps a string payload, id and timestamp as given", async () => {
    const signed = await signOutgoingWebhook({
      secret: "whsec_c2VjcmV0",
      payload: '{"a":1}',
      id: "msg_fixed",
      timestamp: 1700000000,
    });
    expect(signed).toMatchObject({
      id: "msg_fixed",
      timestamp: 1700000000,
      body: '{"a":1}',
    });
    expect(signed.headers["webhook-timestamp"]).toBe("1700000000");
  });

  it("requires a non-empty secret", async () => {
    await expect(
      signOutgoingWebhook({ secret: ["", ""], payload }),
    ).rejects.toThrow(/secret is required/);
  });
});

describe("sendWebhook", () => {
  it("POSTs a signed request and reports a 2xx as ok", async () => {
    const secret = generateWebhookSecret();
    const { fn, calls } = fakeFetch(new Response("thanks", { status: 202 }));
    const result = await sendWebhook(URL_, {
      secret,
      payload,
      headers: { "x-tenant": "t1", "webhook-signature": "forged" },
      fetch: fn,
    });
    expect(result).toMatchObject({
      ok: true,
      status: 202,
      responseBody: "thanks",
    });

    const { init } = calls[0];
    expect(init).toMatchObject({ method: "POST", redirect: "manual" });
    const headers = init.headers as Headers;
    expect(headers.get("x-tenant")).toBe("t1");
    expect(headers.get("webhook-id")).toBe(result.id);
    const verified = await verifyWebhook(
      "standard-webhooks",
      { headers: Object.fromEntries(headers), body: init.body as string },
      secret,
    );
    expect(verified.valid, "extra headers must not replace the signature").toBe(
      true,
    );
  });

  it("reports non-2xx, redirects and network errors without throwing", async () => {
    const opts = { secret: generateWebhookSecret(), payload };
    const failed = await sendWebhook(URL_, {
      ...opts,
      fetch: fakeFetch(new Response("down", { status: 503 })).fn,
    });
    expect(failed).toMatchObject({
      ok: false,
      status: 503,
      responseBody: "down",
    });

    const redirect = await sendWebhook(URL_, {
      ...opts,
      fetch: fakeFetch(
        new Response(null, {
          status: 302,
          headers: { location: "http://10.0.0.1/" },
        }),
      ).fn,
    });
    expect(redirect.ok).toBe(false);
    expect(redirect.error?.message).toMatch(/Redirect \(302\) not followed/);

    const network = await sendWebhook(URL_, {
      ...opts,
      fetch: fakeFetch(new TypeError("fetch failed")).fn,
    });
    expect(network.ok).toBe(false);
    expect(network.status).toBeUndefined();
    expect(network.error?.message).toBe("fetch failed");
  });

  it("times out", async () => {
    const hang = (async (_url: string, init?: RequestInit) =>
      new Promise((_resolve, reject) => {
        init!.signal!.addEventListener("abort", () =>
          reject(init!.signal!.reason),
        );
      })) as unknown as typeof fetch;
    const result = await sendWebhook(URL_, {
      secret: generateWebhookSecret(),
      payload,
      timeoutMs: 20,
      fetch: hang,
    });
    expect(result.ok).toBe(false);
    expect(result.error?.name).toBe("TimeoutError");
  });

  it.each([
    "http://localhost:3000/hook",
    "http://169.254.169.254/latest/meta-data",
    "http://10.0.0.5/hook",
    "http://[::1]/hook",
    "ftp://example.com/hook",
    "not a url",
  ])("refuses %s without sending", async (url) => {
    const { fn } = fakeFetch(new Response("ok"));
    const result = await sendWebhook(url, {
      secret: generateWebhookSecret(),
      payload,
      fetch: fn,
    });
    expect(result.ok).toBe(false);
    expect(result.error).toBeInstanceOf(Error);
    expect(fn).not.toHaveBeenCalled();
  });

  it("allowPrivateNetworks permits local targets", async () => {
    const { fn } = fakeFetch(new Response("ok"));
    const result = await sendWebhook("http://localhost:3000/hook", {
      secret: generateWebhookSecret(),
      payload,
      allowPrivateNetworks: true,
      fetch: fn,
    });
    expect(result.ok).toBe(true);
  });
});

describe("sendWebhook with the real fetch", () => {
  it("delivers to a local server and does not follow redirects", async () => {
    const { createServer } = await import("node:http");
    const received: string[] = [];
    const server = createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        received.push(`${req.url} ${req.headers["webhook-id"]} ${body}`);
        if (req.url === "/redirect") {
          res.writeHead(302, { location: "/elsewhere" }).end();
        } else {
          res.writeHead(200).end("ok");
        }
      });
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const { port } = server.address() as { port: number };
    const opts = {
      secret: generateWebhookSecret(),
      payload,
      allowPrivateNetworks: true,
    };
    try {
      const ok = await sendWebhook(`http://127.0.0.1:${port}/hook`, opts);
      expect(ok).toMatchObject({ ok: true, status: 200, responseBody: "ok" });

      const redirect = await sendWebhook(
        `http://127.0.0.1:${port}/redirect`,
        opts,
      );
      expect(redirect).toMatchObject({ ok: false, status: 302 });
      expect(received.map((r) => r.split(" ")[0])).toEqual([
        "/hook",
        "/redirect",
      ]);
      expect(received[0]).toContain(ok.id);
    } finally {
      server.close();
    }
  });
});
