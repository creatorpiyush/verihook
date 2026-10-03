/**
 * GitLab webhooks. Two schemes, picked by the headers GitLab sends:
 *
 * - Signing token (GitLab 19.1+, recommended): Standard Webhooks. HMAC-SHA256 of
 *   `<webhook-id>.<webhook-timestamp>.<body>` keyed with the base64 token
 *   (`whsec_...`), sent as `webhook-signature: v1,<base64>`. Replay-protected.
 * - Secret token (legacy): the token itself, in plain text:
 *   X-Gitlab-Token: <secret token>
 *
 * Pass whichever you configured on the webhook as the secret.
 * https://docs.gitlab.com/user/project/integrations/webhooks/
 */
import { timingSafeEqual } from "../core/crypto.js";
import { readString } from "../core/event.js";
import {
  NormalizedWebhookRequest,
  ProviderVerifier,
  VerificationResult,
  VerifyWebhookOptions,
  WebhookErrorCode,
} from "../core/types.js";
import { verifySvixStyle } from "./svix.js";

export const gitlabVerifier: ProviderVerifier = {
  name: "gitlab",
  // `object_kind` (e.g. `push`, `merge_request`); `X-Gitlab-Event` (e.g. `Push Hook`) otherwise.
  eventType: (event, req) =>
    readString(event, "object_kind") ?? req.headers["x-gitlab-event"],
  async verify(
    req: NormalizedWebhookRequest,
    secret: string,
    options?: VerifyWebhookOptions,
  ): Promise<VerificationResult> {
    if (req.headers["webhook-signature"]) {
      return verifySvixStyle("gitlab", "webhook", req, secret, options);
    }

    const token = req.headers["x-gitlab-token"];
    if (!token) {
      return {
        valid: false,
        provider: "gitlab",
        code: WebhookErrorCode.MISSING_HEADER,
        reason:
          'Missing "webhook-signature" or "x-gitlab-token" header (set a signing or secret token on the webhook)',
      };
    }

    if (!timingSafeEqual(token, secret)) {
      return {
        valid: false,
        provider: "gitlab",
        code: WebhookErrorCode.INVALID_SIGNATURE,
        reason: "Secret token mismatch",
      };
    }

    return { valid: true, provider: "gitlab" };
  },
};
