import { WebhookLoggerFn } from "./types.js";

let globalLogger: WebhookLoggerFn | undefined;

/**
 * Registers a global telemetry logger callback invoked on every webhook verification attempt.
 * Useful for application-wide observability (Datadog, Winston, Pino, Axiom, Console, Sentry, OpenTelemetry).
 *
 * @param logger Callback function receiving structured `WebhookVerificationEvent`.
 */
export function setGlobalLogger(logger?: WebhookLoggerFn): void {
  globalLogger = logger;
}

/**
 * Retrieves the currently registered global telemetry logger callback.
 */
export function getGlobalLogger(): WebhookLoggerFn | undefined {
  return globalLogger;
}

/**
 * Clears the currently registered global telemetry logger callback.
 */
export function clearGlobalLogger(): void {
  globalLogger = undefined;
}
