import type { ProviderName, VerificationResult } from "../core/types.js";
import type { ResolveEvent } from "../core/event-types.js";
import {
  createWebAdapter,
  DEFAULT_MAX_BODY_SIZE,
  PayloadTooLargeError,
  readNodeBodyWithLimit,
  type SecretResolver,
  type WebAdapterOptions,
} from "./shared.js";

interface NodeRequestLike extends AsyncIterable<Uint8Array | string> {
  headers: Record<string, string | string[] | undefined>;
  method?: string;
  url?: string;
  rawBody?: unknown;
  body?: unknown;
  socket?: unknown;
}

/**
 * The parts of an h3 `H3Event` the handler uses: `event.req` (a Fetch `Request`) on
 * h3 v2, or `event.node.req` on h3 v1 / Nuxt 3.
 */
export interface H3EventLike {
  req?: unknown;
  web?: { request?: Request };
  node?: { req: NodeRequestLike };
}

export type VerihookH3Options<Event extends H3EventLike = H3EventLike> =
  WebAdapterOptions<Event>;

/** `result.event` is the parsed payload, typed for built-in providers. */
export type H3WebhookCallback<
  TEvent = unknown,
  Event extends H3EventLike = H3EventLike,
> = (
  payload: unknown,
  result: VerificationResult<TEvent>,
  event: Event,
) => Promise<Response | void> | Response | void;

function isWebRequest(value: unknown): value is Request {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as Request).clone === "function" &&
    typeof (value as Request).text === "function"
  );
}

function firstHeader(value: string | string[] | undefined): string | undefined {
  return (Array.isArray(value) ? value[0] : value)?.split(",")[0]?.trim();
}

/** Rebuilds a Fetch `Request` from h3 v1's Node.js request. */
async function toWebRequest(
  nodeReq: NodeRequestLike,
  maxBytes: number,
): Promise<Request> {
  const headers = new Headers();
  for (const [key, value] of Object.entries(nodeReq.headers)) {
    if (value === undefined) continue;
    for (const v of Array.isArray(value) ? value : [value]) {
      headers.append(key, v);
    }
  }

  // Some presets (serverless) hand over an already-buffered body instead of a stream.
  const buffered = [nodeReq.rawBody, nodeReq.body].find(
    (b) => typeof b === "string" || b instanceof Uint8Array,
  ) as string | Uint8Array | undefined;
  let body: string;
  if (buffered !== undefined) {
    if (Buffer.byteLength(buffered) > maxBytes)
      throw new PayloadTooLargeError();
    body =
      typeof buffered === "string"
        ? buffered
        : Buffer.from(buffered).toString("utf-8");
  } else {
    const bytes = await readNodeBodyWithLimit(nodeReq, maxBytes);
    // h3's readBody()/readRawBody() check `req.rawBody` first, so handlers can still read it.
    nodeReq.rawBody = bytes;
    body = bytes.toString("utf-8");
  }

  const proto =
    firstHeader(nodeReq.headers["x-forwarded-proto"]) ||
    ((nodeReq.socket as { encrypted?: boolean } | undefined)?.encrypted
      ? "https"
      : "http");
  const host =
    firstHeader(nodeReq.headers["x-forwarded-host"]) ||
    firstHeader(nodeReq.headers.host) ||
    "localhost";
  const method = nodeReq.method || "POST";
  return new Request(`${proto}://${host}${nodeReq.url || "/"}`, {
    method,
    headers,
    body: method === "GET" || method === "HEAD" ? undefined : body,
  });
}

/**
 * h3 / Nuxt / Nitro event handler that verifies the webhook before calling `handler`.
 * Works with h3 v1 (Nuxt 3) and h3 v2.
 *
 * ```ts
 * // server/api/webhooks/stripe.post.ts
 * export default defineEventHandler(
 *   createWebhookHandler("stripe", process.env.STRIPE_WEBHOOK_SECRET!, async (payload, result, event) => {
 *     // result.event is a typed Stripe event
 *   }),
 * );
 * ```
 */
export function createWebhookHandler<
  TEvent = never,
  P extends ProviderName = ProviderName,
  Event extends H3EventLike = H3EventLike,
>(
  provider: P,
  secret: SecretResolver<Event>,
  handler: H3WebhookCallback<ResolveEvent<TEvent, P>, Event>,
  options?: VerihookH3Options<Event>,
): (event: Event) => Promise<Response> {
  const maxBytes = options?.maxBodySize ?? DEFAULT_MAX_BODY_SIZE;
  return createWebAdapter(provider, secret, handler, options, (event) => {
    if (isWebRequest(event.req)) return event.req;
    if (isWebRequest(event.web?.request)) return event.web.request;
    if (event.node?.req) return toWebRequest(event.node.req, maxBytes);
    throw new Error("[verihook] Unsupported h3 event: no request found");
  });
}
