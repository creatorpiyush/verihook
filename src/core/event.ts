import { NormalizedWebhookRequest, ProviderVerifier } from "./types.js";

/** Reads a string at `path` in a parsed payload, or `undefined`. */
export function readString(
  value: unknown,
  ...path: string[]
): string | undefined {
  let current = value;
  for (const key of path) {
    if (!current || typeof current !== "object") return undefined;
    current = (current as Record<string, unknown>)[key];
  }
  return typeof current === "string" && current ? current : undefined;
}

/**
 * Parses a verified body: JSON, or form fields for
 * `application/x-www-form-urlencoded` requests. Other bodies give `undefined`.
 */
export function parseEvent(req: NormalizedWebhookRequest): unknown {
  const contentType = req.headers["content-type"] || "";
  if (contentType.includes("application/x-www-form-urlencoded")) {
    return Object.fromEntries(new URLSearchParams(req.rawBody));
  }
  try {
    return JSON.parse(req.rawBody);
  } catch {
    return undefined;
  }
}

/** Common envelope fields, used when a provider defines no `eventType`. */
function defaultEventType(event: unknown): string | undefined {
  return (
    readString(event, "type") ??
    readString(event, "event") ??
    readString(event, "event_type")
  );
}

export function resolveEventType(
  verifier: ProviderVerifier,
  event: unknown,
  req: NormalizedWebhookRequest,
): string | undefined {
  try {
    return (
      (verifier.eventType
        ? verifier.eventType(event, req)
        : defaultEventType(event)) || undefined
    );
  } catch {
    // A custom provider's eventType must never fail an authentic webhook.
    return undefined;
  }
}
