import { MemoryDedupeStore } from "../../src/index.js";
import { signWebhook } from "../../src/testing.js";

export const SECRET = "whsec_adapter_test_secret";

export function signStripe(id = "evt_adapter_1", extra = {}) {
  return signWebhook("stripe", {
    secret: SECRET,
    payload: { id, type: "invoice.paid", object: "event", ...extra },
  });
}

export function webRequest(signed: {
  url: string;
  headers: Record<string, string>;
  body: string;
}): Request {
  return new Request(signed.url, {
    method: "POST",
    headers: signed.headers,
    body: signed.body,
  });
}

export function tamper(headers: Record<string, string>) {
  return {
    ...headers,
    "stripe-signature": headers["stripe-signature"].replace(/v1=\w/, (m) =>
      m.endsWith("0") ? "v1=1" : "v1=0",
    ),
  };
}

export function dedupeOptions() {
  return { dedupeStore: new MemoryDedupeStore() };
}
