import { ProviderName, ProviderVerifier } from "../core/types.js";
import { UnsupportedProviderError } from "../core/errors.js";
import { githubVerifier } from "./github.js";
import { linearVerifier } from "./linear.js";
import { razorpayVerifier } from "./razorpay.js";
import { shopifyVerifier } from "./shopify.js";
import { slackVerifier } from "./slack.js";
import { squareVerifier } from "./square.js";
import { stripeVerifier } from "./stripe.js";
import { svixVerifier } from "./svix.js";
import { twilioVerifier } from "./twilio.js";
import { zoomVerifier } from "./zoom.js";
import { metaVerifier } from "./meta.js";
import { discordVerifier } from "./discord.js";
import { twitterVerifier } from "./twitter.js";
import { paypalVerifier } from "./paypal.js";
import { lemonsqueezyVerifier } from "./lemonsqueezy.js";
import { paddleVerifier } from "./paddle.js";
import { pagerdutyVerifier } from "./pagerduty.js";
import { webflowVerifier } from "./webflow.js";
import { workosVerifier } from "./workos.js";
import { cashfreeVerifier } from "./cashfree.js";
import { phonepeVerifier } from "./phonepe.js";
import { mollieVerifier } from "./mollie.js";
import { adyenVerifier } from "./adyen.js";
import { checkoutVerifier } from "./checkout.js";
import { authorizenetVerifier } from "./authorizenet.js";
import { recurlyVerifier } from "./recurly.js";
import { gitlabVerifier } from "./gitlab.js";
import { bitbucketVerifier } from "./bitbucket.js";
import { vercelVerifier } from "./vercel.js";
import { sentryVerifier } from "./sentry.js";
import { twitchVerifier } from "./twitch.js";
import { telegramVerifier } from "./telegram.js";
import { postmarkVerifier } from "./postmark.js";
import { sendgridVerifier } from "./sendgrid.js";
import { mailgunVerifier } from "./mailgun.js";
import { hubspotVerifier } from "./hubspot.js";
import { intercomVerifier } from "./intercom.js";
import { calendlyVerifier } from "./calendly.js";
import { typeformVerifier } from "./typeform.js";
import { genericVerifier } from "./generic.js";

export const providers: Record<string, ProviderVerifier> = {
  stripe: stripeVerifier,
  github: githubVerifier,
  shopify: shopifyVerifier,
  slack: slackVerifier,
  twilio: twilioVerifier,
  svix: svixVerifier,
  resend: svixVerifier, // Resend uses Svix
  clerk: svixVerifier, // Clerk uses Svix
  meta: metaVerifier, // Meta / WhatsApp / Instagram / Facebook
  whatsapp: metaVerifier,
  facebook: metaVerifier,
  instagram: metaVerifier,
  discord: discordVerifier, // Discord Interactions Ed25519
  twitter: twitterVerifier, // Twitter / X API
  x: twitterVerifier,
  paypal: paypalVerifier,
  lemonsqueezy: lemonsqueezyVerifier,
  paddle: paddleVerifier,
  pagerduty: pagerdutyVerifier,
  webflow: webflowVerifier,
  workos: workosVerifier,
  linear: linearVerifier,
  razorpay: razorpayVerifier,
  square: squareVerifier,
  zoom: zoomVerifier,
  cashfree: cashfreeVerifier,
  phonepe: phonepeVerifier,
  mollie: mollieVerifier,
  adyen: adyenVerifier,
  checkout: checkoutVerifier,
  authorizenet: authorizenetVerifier,
  recurly: recurlyVerifier,
  gitlab: gitlabVerifier,
  bitbucket: bitbucketVerifier,
  vercel: vercelVerifier,
  sentry: sentryVerifier,
  twitch: twitchVerifier,
  telegram: telegramVerifier,
  postmark: postmarkVerifier,
  sendgrid: sendgridVerifier,
  mailgun: mailgunVerifier,
  hubspot: hubspotVerifier,
  intercom: intercomVerifier,
  calendly: calendlyVerifier,
  typeform: typeformVerifier,
  generic: genericVerifier,
};

export function getProviderVerifier(name: ProviderName): ProviderVerifier {
  const key = String(name).toLowerCase();
  // Own-property check so names like "constructor" or "__proto__" never resolve.
  const provider = Object.prototype.hasOwnProperty.call(providers, key)
    ? providers[key]
    : undefined;
  if (!provider) {
    throw new UnsupportedProviderError(String(name), Object.keys(providers));
  }
  return provider;
}

const RESERVED_PROVIDER_NAMES = new Set([
  "__proto__",
  "constructor",
  "prototype",
]);

export function registerProvider(verifier: ProviderVerifier): void {
  const key = String(verifier.name).toLowerCase();
  if (RESERVED_PROVIDER_NAMES.has(key)) {
    throw new Error(`[verihook] Invalid provider name "${verifier.name}"`);
  }
  providers[key] = verifier;
}

export {
  githubVerifier,
  linearVerifier,
  razorpayVerifier,
  shopifyVerifier,
  slackVerifier,
  squareVerifier,
  stripeVerifier,
  svixVerifier,
  twilioVerifier,
  zoomVerifier,
  metaVerifier,
  discordVerifier,
  twitterVerifier,
  paypalVerifier,
  lemonsqueezyVerifier,
  paddleVerifier,
  pagerdutyVerifier,
  webflowVerifier,
  workosVerifier,
  cashfreeVerifier,
  phonepeVerifier,
  mollieVerifier,
  adyenVerifier,
  checkoutVerifier,
  authorizenetVerifier,
  recurlyVerifier,
  gitlabVerifier,
  bitbucketVerifier,
  vercelVerifier,
  sentryVerifier,
  twitchVerifier,
  telegramVerifier,
  postmarkVerifier,
  sendgridVerifier,
  mailgunVerifier,
  hubspotVerifier,
  intercomVerifier,
  calendlyVerifier,
  typeformVerifier,
  genericVerifier,
};
