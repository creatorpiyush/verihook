/** `verihook/paddle`: verifies only this provider, without bundling the others. */
import { bindVerifier } from "../core/provider-entry.js";
import { paddleVerifier } from "../providers/paddle.js";

export const verifyPaddle = bindVerifier("paddle", paddleVerifier);

export { paddleVerifier };
export type { PaddleEvent } from "../core/event-types.js";
export { WebhookErrorCode } from "../core/types.js";
export type {
  VerificationResult,
  VerifyWebhookOptions,
  WebhookRequestInput,
} from "../core/types.js";
