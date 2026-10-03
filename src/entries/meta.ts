/** `verihook/meta`: verifies only this provider, without bundling the others. */
import { bindVerifier } from "../core/provider-entry.js";
import { metaVerifier } from "../providers/meta.js";

export const verifyMeta = bindVerifier("meta", metaVerifier);
export const verifyWhatsApp = bindVerifier("whatsapp", metaVerifier);

export { metaVerifier };
export { verifyMetaChallenge } from "../providers/meta.js";
export type {
  MetaChallengeQueryParams,
  MetaChallengeResult,
} from "../providers/meta.js";
export type { MetaEvent } from "../core/event-types.js";
export { WebhookErrorCode } from "../core/types.js";
export type {
  VerificationResult,
  VerifyWebhookOptions,
  WebhookRequestInput,
} from "../core/types.js";
