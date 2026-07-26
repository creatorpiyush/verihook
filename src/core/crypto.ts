import { stringToBytes } from '../utils/encoding.js';

/**
 * Perform constant-time comparison of two strings or Uint8Arrays to prevent timing attacks.
 */
export function timingSafeEqual(
  a: string | Uint8Array,
  b: string | Uint8Array
): boolean {
  const bytesA = typeof a === 'string' ? stringToBytes(a) : a;
  const bytesB = typeof b === 'string' ? stringToBytes(b) : b;

  if (bytesA.length !== bytesB.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < bytesA.length; i++) {
    result |= bytesA[i] ^ bytesB[i];
  }

  return result === 0;
}

/**
 * Computes a SHA-256 hash digest.
 */
export async function computeSha256(data: string | Uint8Array): Promise<Uint8Array> {
  const dataBytes = typeof data === 'string' ? stringToBytes(data) : data;
  const cryptoSubtle = globalThis.crypto?.subtle;

  if (cryptoSubtle) {
    const hash = await cryptoSubtle.digest('SHA-256', dataBytes as unknown as BufferSource);
    return new Uint8Array(hash);
  }

  try {
    const nodeCrypto = await import('node:crypto');
    const hash = nodeCrypto.createHash('sha256');
    hash.update(Buffer.from(dataBytes));
    return new Uint8Array(hash.digest());
  } catch (err) {
    throw new Error('Crypto API unavailable for computing SHA-256 hash');
  }
}

/**
 * Computes an HMAC digest using Web Crypto API.
 */
export async function computeHmac(
  algorithm: 'SHA-256' | 'SHA-1' | 'SHA-512',
  secret: string | Uint8Array,
  data: string | Uint8Array
): Promise<Uint8Array> {
  const secretBytes = typeof secret === 'string' ? stringToBytes(secret) : secret;
  const dataBytes = typeof data === 'string' ? stringToBytes(data) : data;

  const cryptoSubtle = globalThis.crypto?.subtle;

  if (cryptoSubtle) {
    const key = await cryptoSubtle.importKey(
      'raw',
      secretBytes as unknown as BufferSource,
      { name: 'HMAC', hash: { name: algorithm } },
      false,
      ['sign']
    );

    const signature = await cryptoSubtle.sign('HMAC', key, dataBytes as unknown as BufferSource);
    return new Uint8Array(signature);
  }

  try {
    const nodeCrypto = await import('node:crypto');
    const nodeAlg = algorithm.replace('-', '').toLowerCase();
    const hmac = nodeCrypto.createHmac(nodeAlg, Buffer.from(secretBytes));
    hmac.update(Buffer.from(dataBytes));
    return new Uint8Array(hmac.digest());
  } catch (err) {
    throw new Error(`Crypto API unavailable for computing HMAC ${algorithm}`);
  }
}

export function computeHmacSha256(
  secret: string | Uint8Array,
  data: string | Uint8Array
): Promise<Uint8Array> {
  return computeHmac('SHA-256', secret, data);
}

export function computeHmacSha1(
  secret: string | Uint8Array,
  data: string | Uint8Array
): Promise<Uint8Array> {
  return computeHmac('SHA-1', secret, data);
}

export function computeHmacSha512(
  secret: string | Uint8Array,
  data: string | Uint8Array
): Promise<Uint8Array> {
  return computeHmac('SHA-512', secret, data);
}
