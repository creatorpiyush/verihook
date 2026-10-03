/** `verihook/square`: verifies only this provider, without bundling the others. */
import { bindVerifier } from "../core/provider-entry.js";
import { squareVerifier } from "../providers/square.js";

export const verifySquare = bindVerifier("square", squareVerifier);

export { squareVerifier };
export type { SquareEvent } from "../core/event-types.js";
export { WebhookErrorCode } from "../core/types.js";
export type {
  VerificationResult,
  VerifyWebhookOptions,
  WebhookRequestInput,
} from "../core/types.js";
