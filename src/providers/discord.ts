import { verifyEd25519 } from "../core/crypto.js";
import {
  NormalizedWebhookRequest,
  ProviderVerifier,
  VerificationResult,
  VerifyWebhookOptions,
  WebhookErrorCode,
} from "../core/types.js";

import { toEpochSeconds } from "../utils/timestamp.js";
import { readString } from "../core/event.js";

const DISCORD_TYPES: Record<number, string> = {
  0: "PING",
  1: "PING",
  2: "APPLICATION_COMMAND",
  3: "MESSAGE_COMPONENT",
  4: "APPLICATION_COMMAND_AUTOCOMPLETE",
  5: "MODAL_SUBMIT",
};

export const discordVerifier: ProviderVerifier = {
  name: "discord",
  eventType(event) {
    // Webhook events carry `event.type`; interactions only a numeric `type`.
    const name = readString(event, "event", "type");
    if (name) return name;
    const type = (event as { type?: unknown } | undefined)?.type;
    return typeof type === "number" ? DISCORD_TYPES[type] : undefined;
  },
  async verify(
    req: NormalizedWebhookRequest,
    secret: string,
    options?: VerifyWebhookOptions,
  ): Promise<VerificationResult> {
    const signature = req.headers["x-signature-ed25519"];
    const timestampStr = req.headers["x-signature-timestamp"];

    if (!signature) {
      return {
        valid: false,
        provider: "discord",
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Missing "x-signature-ed25519" header',
      };
    }

    if (!timestampStr) {
      return {
        valid: false,
        provider: "discord",
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Missing "x-signature-timestamp" header',
      };
    }

    const rawTimestamp = parseInt(timestampStr, 10);
    if (isNaN(rawTimestamp)) {
      return {
        valid: false,
        provider: "discord",
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Invalid "x-signature-timestamp" header format',
      };
    }

    const timestamp = toEpochSeconds(rawTimestamp);
    const tolerance = options?.tolerance ?? 300;
    if (tolerance > 0) {
      const now = toEpochSeconds(options?.now ?? Math.floor(Date.now() / 1000));
      if (Math.abs(now - timestamp) > tolerance) {
        return {
          valid: false,
          provider: "discord",
          code: WebhookErrorCode.EXPIRED_TIMESTAMP,
          timestamp,
          reason: `Timestamp outside tolerance window (timestamp: ${timestamp}, current: ${now}, tolerance: ${tolerance}s)`,
        };
      }
    }

    const payloadToSign = `${timestampStr}${req.rawBody}`;
    const isValid = await verifyEd25519(secret, signature, payloadToSign);

    if (!isValid) {
      return {
        valid: false,
        provider: "discord",
        code: WebhookErrorCode.INVALID_SIGNATURE,
        timestamp,
        reason: "Ed25519 signature mismatch",
      };
    }

    return {
      valid: true,
      provider: "discord",
      timestamp,
    };
  },
};
