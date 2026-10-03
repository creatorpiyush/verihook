/** `verihook/github`: verifies only this provider, without bundling the others. */
import { bindVerifier } from "../core/provider-entry.js";
import { githubVerifier } from "../providers/github.js";

export const verifyGitHub = bindVerifier("github", githubVerifier);

export { githubVerifier };
export type { GitHubEvent } from "../core/event-types.js";
export { WebhookErrorCode } from "../core/types.js";
export type {
  VerificationResult,
  VerifyWebhookOptions,
  WebhookRequestInput,
} from "../core/types.js";
