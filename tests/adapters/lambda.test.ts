import { describe, expect, it, vi } from "vitest";
import {
  createWebhookHandler,
  type LambdaHttpEvent,
} from "../../src/lambda.js";
import { signWebhook } from "../../src/testing.js";
import { dedupeOptions, SECRET, signStripe, tamper } from "./helpers.js";

function v2Event(
  signed: { headers: Record<string, string>; body: string },
  extra: Partial<LambdaHttpEvent> = {},
): LambdaHttpEvent {
  return {
    rawPath: "/webhooks/stripe",
    rawQueryString: "",
    headers: signed.headers,
    body: signed.body,
    isBase64Encoded: false,
    requestContext: {
      domainName: "abc.lambda-url.us-east-1.on.aws",
      http: { method: "POST" },
    },
    ...extra,
  };
}

describe("verihook/lambda", () => {
  it("verifies an HTTP API v2 / Function URL event and passes event + context", async () => {
    const handler = vi.fn();
    const lambda = createWebhookHandler("stripe", SECRET, handler);
    const signed = await signStripe();

    const res = await lambda(v2Event(signed), { awsRequestId: "req-1" });

    expect(res.statusCode).toBe(200);
    expect(JSON.parse(res.body!)).toEqual({ received: true });
    const [payload, result, , context] = handler.mock.calls[0];
    expect(payload).toMatchObject({ id: "evt_adapter_1" });
    expect(result.eventType).toBe("invoice.paid");
    expect(context).toEqual({ awsRequestId: "req-1" });
  });

  it("decodes base64 bodies", async () => {
    const lambda = createWebhookHandler("stripe", SECRET, () => ({
      statusCode: 204,
    }));
    const signed = await signStripe();
    const res = await lambda(
      v2Event(signed, {
        body: Buffer.from(signed.body).toString("base64"),
        isBase64Encoded: true,
      }),
      {},
    );
    expect(res.statusCode).toBe(204);
  });

  it("rebuilds the signed URL for Twilio (v2 with query, v1 with stage)", async () => {
    const url = "https://hooks.example.com/prod/webhooks/twilio?tenant=a";
    const signed = await signWebhook("twilio", {
      secret: "twilio_token",
      url,
      form: { CallSid: "CA1", From: "+15550001" },
    });
    const lambda = createWebhookHandler("twilio", "twilio_token", () => {});
    const headers = { ...signed.headers, host: "hooks.example.com" };

    const v2 = await lambda(
      v2Event(
        { headers, body: signed.body },
        {
          rawPath: "/prod/webhooks/twilio",
          rawQueryString: "tenant=a",
        },
      ),
      {},
    );
    const v1 = await lambda(
      {
        httpMethod: "POST",
        path: "/webhooks/twilio",
        queryStringParameters: { tenant: "a" },
        headers,
        body: signed.body,
        requestContext: {
          path: "/prod/webhooks/twilio",
          domainName: "hooks.example.com",
        },
      },
      {},
    );

    expect(v2.statusCode).toBe(200);
    expect(v1.statusCode).toBe(200);
  });

  it("rejects forged signatures and oversized bodies, and supports onError", async () => {
    const signed = await signStripe();
    const forged = v2Event({ ...signed, headers: tamper(signed.headers) });

    const res = await createWebhookHandler("stripe", SECRET, () => {})(
      forged,
      {},
    );
    expect(res.statusCode).toBe(401);
    expect(res.headers?.["X-Content-Type-Options"]).toBe("nosniff");
    expect(JSON.parse(res.body!).code).toBe("INVALID_SIGNATURE");

    const small = createWebhookHandler("stripe", SECRET, () => {}, {
      maxBodySize: 5,
    });
    expect((await small(v2Event(signed), {})).statusCode).toBe(413);

    const custom = createWebhookHandler("stripe", SECRET, () => {}, {
      onError: (result) => ({ statusCode: 418, body: String(result.code) }),
    });
    expect(await custom(forged, {})).toEqual({
      statusCode: 418,
      body: "INVALID_SIGNATURE",
    });
  });

  it("handles a missing body and a throwing secret resolver", async () => {
    const lambda = createWebhookHandler("stripe", SECRET, () => {});
    expect((await lambda({ headers: null, body: null }, {})).statusCode).toBe(
      401,
    );
    const broken = createWebhookHandler(
      "stripe",
      () => {
        throw new Error("ssm down");
      },
      () => {},
    );
    const res = await broken(v2Event(await signStripe()), {});
    expect(res.statusCode).toBe(500);
    expect(JSON.parse(res.body!)).toEqual({
      error: "Internal webhook verification error",
    });
  });

  it("releases the event on handler failure or a 5xx result, and acks duplicates", async () => {
    const options = dedupeOptions();
    const outcomes: Array<"throw" | "503" | "ok"> = ["throw", "503", "ok"];
    const lambda = createWebhookHandler(
      "stripe",
      SECRET,
      () => {
        const next = outcomes.shift();
        if (next === "throw") throw new Error("db down");
        if (next === "503") return { statusCode: 503 };
      },
      options,
    );
    const event = v2Event(await signStripe("evt_lambda_retry"));

    expect((await lambda(event, {})).statusCode).toBe(500);
    expect((await lambda(event, {})).statusCode).toBe(503);
    expect((await lambda(event, {})).statusCode).toBe(200);
    const dup = await lambda(event, {});
    expect(JSON.parse(dup.body!)).toEqual({ received: true, duplicate: true });
  });
});
