import { computeSha256 } from "./crypto.js";
import { parseEvent, readString } from "./event.js";
import {
  DedupeStore,
  MemoryDedupeStoreOptions,
  NormalizedWebhookRequest,
  ProviderName,
  VerificationResult,
  VerifyWebhookOptions,
} from "./types.js";
import { bytesToHex } from "../utils/encoding.js";

/**
 * High-performance in-memory deduplication store with TTL management and LRU capacity bounds.
 */
export class MemoryDedupeStore implements DedupeStore {
  private cache = new Map<string, number>();
  private defaultTtlMs: number;
  private maxSize: number;

  constructor(options?: MemoryDedupeStoreOptions) {
    this.defaultTtlMs = options?.ttlMs ?? 300_000; // 5 minutes default
    this.maxSize = options?.maxSize ?? 10_000;
  }

  /**
   * Checks if an event key exists and is non-expired.
   * If not present, adds the key with the specified TTL in milliseconds.
   * @returns `true` if event is a duplicate, `false` if new.
   */
  hasOrSet(key: string, ttlMs?: number): boolean {
    const now = Date.now();
    const effectiveTtl = ttlMs ?? this.defaultTtlMs;

    const existingExpiry = this.cache.get(key);
    if (existingExpiry !== undefined) {
      if (existingExpiry > now) {
        // Refresh key position in Map for accurate LRU ordering
        this.cache.delete(key);
        this.cache.set(key, existingExpiry);
        return true;
      }
      // Expired key, remove before re-adding
      this.cache.delete(key);
    }

    // Drop expired entries from the oldest end so idle keys don't accumulate
    for (const [oldKey, expiry] of this.cache) {
      if (expiry > now) break;
      this.cache.delete(oldKey);
    }

    // LRU eviction if maximum capacity is reached
    if (this.maxSize > 0 && this.cache.size >= this.maxSize) {
      const firstKey = this.cache.keys().next().value;
      if (firstKey !== undefined) {
        this.cache.delete(firstKey);
      }
    }

    this.cache.set(key, now + effectiveTtl);
    return false;
  }

  /**
   * Removes a single event key so a retry of that event is accepted again.
   */
  delete(key: string): void {
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
  paypal: ["paypal-transmission-id"],
  twitch: ["twitch-eventsub-message-id"],
};

/**
 * Extracts the event ID used as the dedupe key. It only reads data the provider's
 * signature covers: a signed ID header, an ID in the signed body, or else a SHA-256
 * digest of the body. Unsigned headers (e.g. `x-github-delivery`) are never used,
 * because a client could change them to slip a replayed webhook past the store.
 */
export async function extractEventId(
  provider: ProviderName,
  req: NormalizedWebhookRequest,
): Promise<string> {
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

  // 3. Common ID properties in the signed JSON body
  if (parsed && typeof parsed === "object") {
    const id =
      readString(parsed, "id") ??
      readString(parsed, "event_id") ??
      readString(parsed, "msg_id") ??
      readString(parsed, "notificationId") ??
      readString(parsed, "messages", "0", "id");
    if (id) return id;
  }

  // 4. SHA-256 digest over provider + raw body
  const hashBytes = await computeSha256(`${provider}:${req.rawBody || ""}`);
  return bytesToHex(hashBytes);
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
    await options.dedupeStore.delete(result.dedupeKey);
  } catch {
    // Best-effort: a failed release only means the retry is treated as a duplicate.
  }
}
