import { readNodeEnv } from "../utils/env.js";
import { normalizeRequest } from "../utils/normalize-request.js";
import { extractEventId } from "./dedupe.js";
import { diagnoseFailure, warnHintOnce } from "./diagnostics.js";
import { parseEvent, resolveEventType } from "./event.js";
import { getGlobalLogger } from "./logger.js";
import {
  ProviderName,
  ProviderVerifier,
  VerificationErrorCode,
  VerificationResult,
  VerifyWebhookOptions,
  WebhookErrorCode,
  WebhookRequestInput,
  WebhookVerificationEvent,
} from "./types.js";

const KNOWN_ERROR_CODES = new Set<string>(Object.values(WebhookErrorCode));

function dispatchTelemetry(
  result: VerificationResult,
  startTime: number,
  attemptedAt: number,
  options?: VerifyWebhookOptions,
): void {
  const durationMs = Math.round((performance.now() - startTime) * 100) / 100;
  const event: WebhookVerificationEvent = {
    provider: result.provider,
    valid: result.valid,
    code: result.code,
    reason: result.reason,
    hint: result.hint,
    eventType: result.eventType,
    timestamp: result.timestamp,
    durationMs,
    attemptedAt,
    error: result.error,
  };

  const perCallLogger = options?.onVerify || options?.log;
  const globalLogger = getGlobalLogger();

  const isDev =
    typeof process !== "undefined" && readNodeEnv() !== "production";

  if (perCallLogger) {
    try {
      Promise.resolve(perCallLogger(event)).catch((err) => {
        if (isDev) {
          console.warn("[verihook] per-call telemetry logger failed:", err);
        }
      });
    } catch (err) {
      if (isDev) {
        console.warn("[verihook] per-call telemetry logger exception:", err);
      }
    }
  }

  if (globalLogger) {
    try {
      Promise.resolve(globalLogger(event)).catch((err) => {
        if (isDev) {
          console.warn("[verihook] global telemetry logger failed:", err);
        }
      });
    } catch (err) {
      if (isDev) {
        console.warn("[verihook] global telemetry logger exception:", err);
      }
    }
  }
}

/**
 * The verification pipeline behind `verifyWebhook` and the per-provider entry points:
 * normalize, verify, diagnose, parse, dedupe and report telemetry. It never imports
 * the provider registry, so a bundle only contains the verifier it is given.
 * `resolveVerifier` runs inside the error handling, so lookup errors become results.
 */
export async function runVerification(
  provider: ProviderName,
  resolveVerifier: () => ProviderVerifier,
  req: WebhookRequestInput,
  secret: string,
  options?: VerifyWebhookOptions,
): Promise<VerificationResult> {
  const attemptedAt = Date.now();
  const startTime = performance.now();

  let result: VerificationResult;
  try {
    const verifier = resolveVerifier();

    if (!secret && verifier.requiresSecret !== false) {
      result = {
        valid: false,
        provider,
        code: WebhookErrorCode.INVALID_SECRET,
        reason: "Webhook secret is required",
      };
    } else {
      const normalizedReq = await normalizeRequest(req);
      result = await verifier.verify(normalizedReq, secret || "", options);

      if (!result.valid && !result.hint) {
        const hint = diagnoseFailure(
          provider,
          normalizedReq,
          secret || "",
          result,
          options,
        );
        if (hint) {
          result = { ...result, hint };
          warnHintOnce(provider, hint);
        }
      }

      if (result.valid) {
        const event = parseEvent(normalizedReq);
        const eventType = resolveEventType(verifier, event, normalizedReq);
        result = { ...result, event, eventType };
      }

      if (result.valid && options?.dedupeStore) {
        const eventId =
          options.eventId || (await extractEventId(provider, normalizedReq));
        const dedupeKey = `${provider}:${eventId}`;
        const ttlMs = options.dedupeTtlMs ?? 300_000;
        const isDuplicate = await options.dedupeStore.hasOrSet(
          dedupeKey,
          ttlMs,
        );
        if (isDuplicate) {
          result = {
            valid: false,
            provider,
            code: WebhookErrorCode.DUPLICATE_EVENT,
            reason: "Duplicate webhook event detected (replay protection)",
            timestamp: result.timestamp,
          };
        } else {
          result = { ...result, dedupeKey };
        }
      }
    }
  } catch (err: unknown) {
    const errObj = err as Record<string, unknown> | null;
    // Only surface our own codes; e.g. Node's "ERR_*" codes map to UNKNOWN_ERROR.
    const code: VerificationErrorCode =
      errObj && KNOWN_ERROR_CODES.has(errObj.code as string)
        ? (errObj.code as VerificationErrorCode)
        : WebhookErrorCode.UNKNOWN_ERROR;
    const message = err instanceof Error ? err.message : String(err);

    result = {
      valid: false,
      provider,
      code,
      reason: message || "Unknown verification error",
      error: err instanceof Error ? err : new Error(String(err)),
    };
  }

  dispatchTelemetry(result, startTime, attemptedAt, options);
  return result;
}
