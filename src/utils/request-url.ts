import { NormalizedWebhookRequest } from "../core/types.js";

function firstHeaderValue(value: string | undefined): string | undefined {
  const first = value?.split(",")[0]?.trim();
  return first || undefined;
}

/**
 * Resolves the absolute public URL a provider signed (Square, Twilio).
 *
 * Frameworks like Express expose only the path (`/webhooks/twilio`), so a relative
 * URL is rebuilt from `x-forwarded-proto` (else `req.protocol`, else https) and
 * `x-forwarded-host` or `host`. Spoofing these headers only changes the data
 * being verified, so it cannot make a forged signature pass. Pass `options.url`
 * to override.
 */
export function resolveSignedUrl(
  req: NormalizedWebhookRequest,
  explicitUrl?: string,
): string | undefined {
  const url = explicitUrl || req.url;
  if (!url || !url.startsWith("/")) {
    return url;
  }

  const host =
    firstHeaderValue(req.headers["x-forwarded-host"]) ||
    firstHeaderValue(req.headers["host"]);
  if (!host) {
    return url;
  }
  const proto =
    firstHeaderValue(req.headers["x-forwarded-proto"]) ||
    req.protocol?.replace(/:$/, "") ||
    "https";
  return `${proto}://${host}${url}`;
}

/**
 * Returns the URL with its default port toggled (added if absent, removed if present).
 * Some proxies add or strip `:443`/`:80`, so providers' SDKs check both forms.
 */
export function toggleDefaultPort(url: string): string | undefined {
  const match = /^(https?):\/\/([^/?#:]+)(:\d+)?(.*)$/i.exec(url);
  if (!match) {
    return undefined;
  }
  const [, scheme, host, port, rest] = match;
  const defaultPort = scheme.toLowerCase() === "https" ? ":443" : ":80";
  if (!port) {
    return `${scheme}://${host}${defaultPort}${rest}`;
  }
  return port === defaultPort ? `${scheme}://${host}${rest}` : undefined;
}
