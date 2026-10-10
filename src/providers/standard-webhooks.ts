/**
 * Standard Webhooks (https://www.standardwebhooks.com): the scheme Svix created,
 * with `webhook-*` headers. HMAC-SHA256 of `<webhook-id>.<webhook-timestamp>.<body>`
 * keyed with the base64 secret (`whsec_` prefix optional), sent as
 *   webhook-signature: v1,<base64>
 * Several space-separated signatures are sent while a secret is rotated.
 * `verihook/send` signs webhooks this way.
 */
import { ProviderVerifier } from "../core/types.js";
import { verifySvixStyle } from "./svix.js";

export const standardWebhooksVerifier: ProviderVerifier = {
  name: "standard-webhooks",
  verify: (req, secret, options) =>
    verifySvixStyle("standard-webhooks", "webhook", req, secret, options),
};
