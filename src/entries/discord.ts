/** `verihook/discord`: verifies only this provider, without bundling the others. */
import { bindVerifier } from "../core/provider-entry.js";
import type { ProviderVerifyFunction } from "../core/types.js";
import { discordVerifier } from "../providers/discord.js";

export const verifyDiscord: ProviderVerifyFunction<"discord"> = bindVerifier(
  "discord",
  discordVerifier,
);

export { discordVerifier };
export type { DiscordEvent } from "../core/event-types.js";
export { WebhookErrorCode } from "../core/types.js";
export type {
  VerificationResult,
  VerifyWebhookOptions,
  WebhookRequestInput,
} from "../core/types.js";
