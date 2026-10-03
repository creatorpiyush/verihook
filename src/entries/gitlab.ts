/** `verihook/gitlab`: verifies only this provider, without bundling the others. */
import { bindVerifier } from "../core/provider-entry.js";
import type { ProviderVerifyFunction } from "../core/types.js";
import { gitlabVerifier } from "../providers/gitlab.js";

export const verifyGitLab: ProviderVerifyFunction<"gitlab"> = bindVerifier(
  "gitlab",
  gitlabVerifier,
);

export { gitlabVerifier };
export type { GitLabEvent } from "../core/event-types.js";
export { WebhookErrorCode } from "../core/types.js";
export type {
  VerificationResult,
  VerifyWebhookOptions,
  WebhookRequestInput,
} from "../core/types.js";
