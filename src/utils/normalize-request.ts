import {
  NormalizedWebhookRequest,
  WebhookHeaders,
  WebhookRequestInput,
  WebhookRequestInputObject,
} from '../core/types.js';
import { InvalidBodyError } from '../core/errors.js';
import { bytesToString } from './encoding.js';

/**
 * Normalizes headers from various input formats into a record of lowercase header keys to string values.
 */
export function normalizeHeaders(headers?: WebhookHeaders): Record<string, string> {
  const result: Record<string, string> = {};

  if (!headers) {
    return result;
  }

  // Standard Web Fetch API Headers or Map
  if (headers && typeof (headers as any).forEach === 'function') {
    (headers as any).forEach((value: string, key: string) => {
      result[key.toLowerCase()] = value;
    });
    return result;
  }

  // Plain object or Express req.headers
  const rawObj = headers as Record<string, string | string[] | undefined>;
  for (const key of Object.keys(rawObj)) {
    const lowerKey = key.toLowerCase();
    const val = rawObj[key];
    if (val !== undefined && val !== null) {
      if (Array.isArray(val)) {
        result[lowerKey] = val.join(', ');
      } else {
        result[lowerKey] = String(val);
      }
    }
  }

  return result;
}

/**
 * Normalizes body input into raw string.
 */
export function normalizeBody(
  bodyInput: string | Uint8Array | ArrayBuffer | Record<string, any> | any,
  isExplicitRawBody = false
): string {
  if (bodyInput === undefined || bodyInput === null) {
    return '';
  }

  if (typeof bodyInput === 'string') {
    return bodyInput;
  }

  if (bodyInput instanceof Uint8Array) {
    return bytesToString(bodyInput);
  }

  if (bodyInput instanceof ArrayBuffer) {
    return bytesToString(new Uint8Array(bodyInput));
  }

  if (typeof Buffer !== 'undefined' && Buffer.isBuffer(bodyInput)) {
    return bodyInput.toString('utf-8');
  }

  if (typeof bodyInput === 'object') {
    if (!isExplicitRawBody) {
      throw new InvalidBodyError();
    }
    return JSON.stringify(bodyInput);
  }

  return String(bodyInput);
}

/**
 * Main normalization function that handles Web Fetch Request objects, Express requests, Next.js requests, etc.
 */
export async function normalizeRequest(
  input: WebhookRequestInput
): Promise<NormalizedWebhookRequest> {
  if (!input) {
    throw new Error('[verihook] Request input cannot be null or undefined');
  }

  // 1. Standard Web Fetch Request (or Request-like object with .clone() and .text())
  if (
    typeof input === 'object' &&
    'headers' in input &&
    typeof (input as Request).clone === 'function' &&
    typeof (input as Request).text === 'function'
  ) {
    const fetchReq = input as Request;
    const cloned = fetchReq.clone();
    const rawBody = await cloned.text();
    const headers = normalizeHeaders(fetchReq.headers);
    return {
      headers,
      rawBody,
      url: fetchReq.url,
      method: fetchReq.method,
    };
  }

  // 2. Plain object input (Express req, Fastify req, custom object)
  const reqObj = input as WebhookRequestInputObject;
  const headers = normalizeHeaders(reqObj.headers);

  const isExplicitRaw = reqObj.rawBody !== undefined;
  const bodySource = isExplicitRaw ? reqObj.rawBody : reqObj.body;
  const rawBody = normalizeBody(bodySource, isExplicitRaw);

  const url = reqObj.originalUrl || reqObj.url;
  const method = reqObj.method;

  return {
    headers,
    rawBody,
    url,
    method,
  };
}
