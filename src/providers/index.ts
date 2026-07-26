import { ProviderName, ProviderVerifier } from '../core/types.js';
import { UnsupportedProviderError } from '../core/errors.js';
import { githubVerifier } from './github.js';
import { linearVerifier } from './linear.js';
import { razorpayVerifier } from './razorpay.js';
import { shopifyVerifier } from './shopify.js';
import { slackVerifier } from './slack.js';
import { squareVerifier } from './square.js';
import { stripeVerifier } from './stripe.js';
import { svixVerifier } from './svix.js';
import { twilioVerifier } from './twilio.js';
import { zoomVerifier } from './zoom.js';
import { genericVerifier } from './generic.js';

export const providers: Record<string, ProviderVerifier> = {
  stripe: stripeVerifier,
  github: githubVerifier,
  shopify: shopifyVerifier,
  slack: slackVerifier,
  twilio: twilioVerifier,
  svix: svixVerifier,
  resend: svixVerifier, // Resend uses Svix
  clerk: svixVerifier,  // Clerk uses Svix
  linear: linearVerifier,
  razorpay: razorpayVerifier,
  square: squareVerifier,
  zoom: zoomVerifier,
  generic: genericVerifier,
};

export function getProviderVerifier(name: ProviderName): ProviderVerifier {
  const key = String(name).toLowerCase();
  const provider = providers[key];
  if (!provider) {
    throw new UnsupportedProviderError(String(name), Object.keys(providers));
  }
  return provider;
}

export function registerProvider(verifier: ProviderVerifier): void {
  providers[verifier.name.toLowerCase()] = verifier;
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
  genericVerifier,
};
