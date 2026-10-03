/**
 * Deno smoke test, run in CI with `deno run --unstable-sloppy-imports tests/deno/smoke.ts`.
 * It runs without permissions, like a locked-down Deno deployment, and loads the
 * TypeScript sources the way JSR serves them.
 */
import { verifyWebhook } from "../../src/index.ts";
import { verifyStripe } from "../../src/entries/stripe.ts";
import { signWebhook } from "../../src/testing.ts";

const secrets: Record<string, string | undefined> = {
  stripe: "whsec_deno_smoke",
  github: "github_deno_smoke",
  svix: "whsec_ZGVub19zbW9rZV9zZWNyZXQ=",
  slack: "slack_deno_smoke",
  twilio: "twilio_deno_smoke",
  discord: undefined,
};

for (const [provider, secret] of Object.entries(secrets)) {
  const hook = await signWebhook(provider, {
    secret,
    payload: { id: "evt_deno", type: "deno.smoke" },
  });
  const request = new Request(hook.url, {
    method: "POST",
    headers: hook.headers,
    body: hook.body,
  });
  const result = await verifyWebhook(provider as never, request, hook.secret);
  if (!result.valid) {
    throw new Error(`${provider} failed under Deno: ${result.reason}`);
  }
  const tampered = await verifyWebhook(
    provider as never,
    { headers: hook.headers, body: hook.body + " ", url: hook.url },
    hook.secret,
  );
  if (tampered.valid) {
    throw new Error(`${provider} accepted a tampered body under Deno`);
  }
}

const hook = await signWebhook("stripe", {
  secret: secrets.stripe,
  payload: { id: "evt_deno", type: "deno.smoke" },
});
const entry = await verifyStripe(
  { headers: hook.headers, body: hook.body },
  secrets.stripe!,
);
if (entry.eventType !== "deno.smoke") {
  throw new Error(`verihook/stripe failed under Deno: ${entry.reason}`);
}

console.log("verihook works under Deno");
