import { computeSha256 } from "./crypto.js";
import { parseEvent, readString } from "./event.js";
import {
  DedupeClaim,
  DedupeStore,
  MemoryDedupeStoreOptions,
  NormalizedWebhookRequest,
  ProviderName,
  ProviderVerifier,
  VerificationResult,
  VerifyWebhookOptions,
} from "./types.js";
import { bytesToHex } from "../utils/encoding.js";
import { readNodeEnv } from "../utils/env.js";
import { adyenSigningString, notificationItems } from "../providers/adyen.js";

/**
 * Default dedupe record lifetime: 24 hours. Many providers sign no timestamp
 * (GitHub, Shopify, Square, ...), so a captured delivery can be replayed as soon
 * as its record expires; a short TTL would reopen that window within minutes.
 */
export const DEFAULT_DEDUPE_TTL_MS = 86_400_000;

/**
 * How long the adapters hold an event as "in progress" before a retry may be
 * processed again. It bounds how long an event is stuck after a crash, and a
 * handler running longer than this can overlap with a retry, so it is a
 * trade-off: 60 seconds covers typical handlers; raise it for slow ones.
 */
export const DEFAULT_DEDUPE_PROCESSING_TTL_MS = 60_000;

interface MemoryEntry {
  expiresAt: number;
  /** Set while the key is claimed and not committed: the claim's owner. */
  token?: string;
}

/** A random claim owner, so a stale delivery can't touch a newer claim. */
export function newDedupeToken(): string {
  return bytesToHex(globalThis.crypto.getRandomValues(new Uint8Array(16)));
}

/**
 * High-performance in-memory deduplication store with TTL management and LRU capacity bounds.
 */
export class MemoryDedupeStore implements DedupeStore {
  private cache = new Map<string, MemoryEntry>();
  private defaultTtlMs: number;
  private maxSize: number;

  constructor(options?: MemoryDedupeStoreOptions) {
    this.defaultTtlMs = options?.ttlMs ?? DEFAULT_DEDUPE_TTL_MS;
    this.maxSize = options?.maxSize ?? 10_000;
  }

  /**
   * Checks if an event key exists and is non-expired.
   * If not present, adds the key with the specified TTL in milliseconds.
   * @returns `true` if event is a duplicate, `false` if new.
   */
  hasOrSet(key: string, ttlMs?: number): boolean {
    return this.take(key, ttlMs ?? this.defaultTtlMs) !== "new";
  }

  /**
   * Records a new key as in progress for `processingTtlMs`, owned by `token`,
   * or reports the state of an existing one. Follow with `commit` once the
   * event is processed.
   */
  claim(key: string, processingTtlMs: number, token: string): DedupeClaim {
    return this.take(key, processingTtlMs, token);
  }

  /**
   * Marks a claimed key as processed and keeps it for `ttlMs`. With `token`,
   * does nothing if another delivery has claimed or committed the key since.
   */
  commit(key: string, ttlMs?: number, token?: string): void {
    const now = Date.now();
    const existing = this.live(key, now);
    if (token !== undefined && existing && existing.token !== token) return;
    this.cache.delete(key);
    this.insert(key, { expiresAt: now + (ttlMs ?? this.defaultTtlMs) }, now);
  }

  /** Returns the key's entry if it hasn't expired. */
  private live(key: string, now: number): MemoryEntry | undefined {
    const entry = this.cache.get(key);
    return entry && entry.expiresAt > now ? entry : undefined;
  }

  private take(key: string, ttlMs: number, token?: string): DedupeClaim {
    const now = Date.now();

    const existing = this.cache.get(key);
    if (existing !== undefined) {
      if (existing.expiresAt > now) {
        // Refresh key position in Map for accurate LRU ordering
        this.cache.delete(key);
        this.cache.set(key, existing);
        return existing.token !== undefined ? "processing" : "done";
      }
      // Expired key, remove before re-adding
      this.cache.delete(key);
    }

    this.insert(key, { expiresAt: now + ttlMs, token }, now);
    return "new";
  }

  /** Adds a key that isn't in the cache, within the `maxSize` bound. */
  private insert(key: string, entry: MemoryEntry, now: number): void {
    // Drop expired entries from the oldest end so idle keys don't accumulate
    for (const [oldKey, old] of this.cache) {
      if (old.expiresAt > now) break;
      this.cache.delete(oldKey);
    }

    // LRU eviction if maximum capacity is reached
    if (this.maxSize > 0 && this.cache.size >= this.maxSize) {
      const firstKey = this.cache.keys().next().value;
      if (firstKey !== undefined) {
        this.cache.delete(firstKey);
      }
    }

    this.cache.set(key, entry);
  }

  /**
   * Removes a single event key so a retry of that event is accepted again.
   * With `token`, only while the key is still claimed with that token.
   */
  delete(key: string, token?: string): void {
    if (token !== undefined && this.cache.get(key)?.token !== token) return;
    this.cache.delete(key);
  }

  /**
   * Clears all stored event entries.
   */
  clear(): void {
    this.cache.clear();
  }

  /**
   * Returns current active cached key count (including potentially expired keys before GC).
   */
  get size(): number {
    return this.cache.size;
  }
}

// Headers whose event ID the provider's signature covers. GitLab's token mode signs
// nothing, but whoever holds its static token can send any request anyway.
const SIGNED_ID_HEADERS: Partial<Record<ProviderName, readonly string[]>> = {
  svix: ["svix-id"],
  resend: ["svix-id"],
  clerk: ["svix-id"],
  gitlab: ["webhook-id", "idempotency-key"],
  "standard-webhooks": ["webhook-id"],
  paypal: ["paypal-transmission-id"],
  twitch: ["twitch-eventsub-message-id"],
};

/**
 * Extracts the event ID used as the dedupe key. It only reads data the provider's
 * signature covers: a signed ID header, an ID in the signed body, Adyen's signed
 * item fields, or else a SHA-256 digest of the body. Unsigned headers (e.g.
 * `x-github-delivery`) are never used, because a client could change them to slip
 * a replayed webhook past the store.
 *
 * Pass the provider's `verifier` so its `dedupeId` hook applies (Mercado Pago,
 * custom providers); `verifyWebhook` always does.
 */
export async function extractEventId(
  provider: ProviderName,
  req: NormalizedWebhookRequest,
  verifier?: Pick<ProviderVerifier, "dedupeId">,
): Promise<string> {
  // 0. The provider's own signed ID
  const fromProvider = verifier?.dedupeId?.(req);
  if (fromProvider) return fromProvider;

  // Mercado Pago doesn't sign its body, so the rules below would key on
  // unsigned data. Only its verifier's dedupeId knows the signed ID.
  if (provider === "mercadopago") {
    throw new TypeError(
      '[verihook] extractEventId("mercadopago") needs the verifier: extractEventId("mercadopago", req, providers.mercadopago)',
    );
  }

  // 1. Signed ID headers for this provider
  for (const name of SIGNED_ID_HEADERS[provider] ?? []) {
    const value = req.headers[name];
    if (value) return value;
  }

  const parsed = req.rawBody ? parseEvent(req) : undefined;

  // 2. Mailgun signs only `timestamp + token`, so its token is the one signed ID
  // (Mailgun recommends rejecting reused tokens).
  if (provider === "mailgun") {
    const token =
      readString(parsed, "signature", "token") ?? readString(parsed, "token");
    if (token) return token;
  }

  // 3. Adyen notification items sign only some fields, so the rest of the body
  // (including any top-level `id`) can't pick the key. Header mode signs the body.
  if (provider === "adyen" && !req.headers["hmacsignature"]) {
    const items = notificationItems(parsed);
    if (items?.length) {
      const signed = items.map(adyenSigningString).join("\n");
      return bytesToHex(await computeSha256(`adyen:${signed}`));
    }
  }

  // 4. Common ID properties in the signed JSON body
  if (parsed && typeof parsed === "object") {
    const id =
      readString(parsed, "id") ??
      readString(parsed, "event_id") ??
      readString(parsed, "msg_id") ??
      readString(parsed, "notificationId") ??
      readString(parsed, "messages", "0", "id");
    if (id) return id;
  }

  // 5. SHA-256 digest over provider + raw body
  const hashBytes = await computeSha256(`${provider}:${req.rawBody || ""}`);
  return bytesToHex(hashBytes);
}

/**
 * Whether these options record events in two phases (claim, then commit): the
 * option is set and the store implements both methods.
 */
export function usesTwoPhaseDedupe(options?: VerifyWebhookOptions): boolean {
  const store = options?.dedupeStore;
  return (
    (options?.dedupeProcessingTtlMs ?? 0) > 0 &&
    typeof store?.claim === "function" &&
    typeof store.commit === "function"
  );
}

/** Store errors after verification are best-effort; say so outside production. */
function warnStoreError(action: string, key: string, err: unknown): void {
  if (typeof process !== "undefined" && readNodeEnv() !== "production") {
    // The key comes from the request: keep it out of the format string, and
    // strip line breaks and escape control characters so it can't forge log lines.
    const safeKey = JSON.stringify(key.replace(/[\r\n]/g, ""));
    console.warn(
      "[verihook] dedupeStore %s failed for %s:",
      action,
      safeKey,
      err,
    );
  }
}

/**
 * Marks a verified event as processed, keeping its dedupe record for the full
 * TTL. Used by the framework middlewares when the webhook handler succeeds.
 * Does nothing unless the event was claimed in two phases.
 */
export async function commitDedupeKey(
  result: VerificationResult,
  options?: VerifyWebhookOptions,
): Promise<void> {
  if (!result.dedupeKey || !usesTwoPhaseDedupe(options)) {
    return;
  }
  try {
    await options!.dedupeStore!.commit!(
      result.dedupeKey,
      options!.dedupeTtlMs ?? DEFAULT_DEDUPE_TTL_MS,
      result.dedupeToken,
    );
  } catch (err) {
    // The claim expires, so a later delivery of this event is processed again.
    warnStoreError("commit", result.dedupeKey, err);
  }
}

/**
 * Removes a verified event's dedupe record so the provider's retry is processed.
 * Used by the framework middlewares when the webhook handler fails.
 */
export async function releaseDedupeKey(
  result: VerificationResult,
  options?: VerifyWebhookOptions,
): Promise<void> {
  if (!result.dedupeKey || !options?.dedupeStore?.delete) {
    return;
  }
  try {
    await options.dedupeStore.delete(result.dedupeKey, result.dedupeToken);
  } catch (err) {
    // The retry is treated as a duplicate (or, when claimed, waits for expiry).
    warnStoreError("delete", result.dedupeKey, err);
  }
}

/**
 * Settles a verified event's dedupe record once the handler's response status
 * is known: released on a 5xx so the provider's retry is processed, committed
 * otherwise.
 */
export function settleDedupeKey(
  result: VerificationResult,
  options: VerifyWebhookOptions | undefined,
  status: number,
): Promise<void> {
  return status >= 500
    ? releaseDedupeKey(result, options)
    : commitDedupeKey(result, options);
}
