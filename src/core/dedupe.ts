import { computeSha256 } from "./crypto.js";
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

/**
 * Extracts provider-specific event ID from normalized headers or JSON body payload,
 * falling back to SHA-256 payload digest.
 */
export async function extractEventId(
  provider: ProviderName,
  req: NormalizedWebhookRequest,
): Promise<string> {
  const headers = req.headers;

  // 1. Direct header extractions
  if (headers["svix-id"]) {
    return headers["svix-id"];
  }
  if (headers["x-github-delivery"]) {
    return headers["x-github-delivery"];
  }
  if (headers["x-shopify-webhook-id"]) {
    return headers["x-shopify-webhook-id"];
  }
  if (headers["paypal-transmission-id"]) {
    return headers["paypal-transmission-id"];
  }

  // 2. Parse JSON body for common ID properties
  if (req.rawBody) {
    try {
      const parsed = JSON.parse(req.rawBody);
      if (parsed && typeof parsed === "object") {
        if (typeof parsed.id === "string" && parsed.id) {
          return parsed.id;
        }
        if (typeof parsed.event_id === "string" && parsed.event_id) {
          return parsed.event_id;
        }
        if (typeof parsed.msg_id === "string" && parsed.msg_id) {
          return parsed.msg_id;
        }
        if (
          Array.isArray(parsed.messages) &&
          parsed.messages[0] &&
          typeof parsed.messages[0].id === "string"
        ) {
          return parsed.messages[0].id;
        }
      }
    } catch {
      // Non-JSON body
    }
  }

  // 3. Provider signature fallback header
  const signatureHeader =
    headers["stripe-signature"] ||
    headers["x-hub-signature-256"] ||
    headers["x-slack-signature"] ||
    headers["paddle-signature"] ||
    headers["x-pagerduty-signature"] ||
    headers["x-webflow-signature"] ||
    headers["x-twilio-signature"];

  if (signatureHeader) {
    return signatureHeader;
  }

  // 4. SHA-256 fallback digest over provider + raw body
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
