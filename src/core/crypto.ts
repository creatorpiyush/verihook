import { base64ToBytes, hexToBytes, stringToBytes } from '../utils/encoding.js';

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
 * Pre-computed CRC32 IEEE 802.3 lookup table.
 */
const CRC32_TABLE = new Uint32Array(256);
for (let i = 0; i < 256; i++) {
  let c = i;
  for (let j = 0; j < 8; j++) {
    c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  }
  CRC32_TABLE[i] = c;
}

/**
 * Computes an IEEE 802.3 CRC-32 checksum (used for PayPal webhook validation).
 */
export function computeCrc32(data: string | Uint8Array): number {
  const bytes = typeof data === 'string' ? stringToBytes(data) : data;
  let crc = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) {
    crc = CRC32_TABLE[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
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
 * Computes an HMAC digest using Web Crypto API or Node crypto fallback.
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

// SPKI header prefix for raw 32-byte Ed25519 public keys
const ED25519_SPKI_HEADER = new Uint8Array([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

/**
 * Verifies an Ed25519 signature against a public key using Web Crypto API / Node crypto fallback.
 */
export async function verifyEd25519(
  publicKey: string | Uint8Array,
  signature: string | Uint8Array,
  data: string | Uint8Array
): Promise<boolean> {
  try {
    const pubBytes = typeof publicKey === 'string' ? hexToBytes(publicKey) : publicKey;
    const sigBytes = typeof signature === 'string' ? hexToBytes(signature) : signature;
    const dataBytes = typeof data === 'string' ? stringToBytes(data) : data;

    if (pubBytes.length !== 32 || sigBytes.length !== 64) {
      return false;
    }

    const cryptoSubtle = globalThis.crypto?.subtle;

    if (cryptoSubtle) {
      const spkiKey = new Uint8Array(ED25519_SPKI_HEADER.length + pubBytes.length);
      spkiKey.set(ED25519_SPKI_HEADER, 0);
      spkiKey.set(pubBytes, ED25519_SPKI_HEADER.length);

      const cryptoKey = await cryptoSubtle.importKey(
        'spki',
        spkiKey as unknown as BufferSource,
        { name: 'Ed25519' },
        false,
        ['verify']
      );

      return await cryptoSubtle.verify(
        { name: 'Ed25519' },
        cryptoKey,
        sigBytes as unknown as BufferSource,
        dataBytes as unknown as BufferSource
      );
    }

    const nodeCrypto = await import('node:crypto');
    const spkiKey = Buffer.concat([Buffer.from(ED25519_SPKI_HEADER), Buffer.from(pubBytes)]);
    const keyObject = nodeCrypto.createPublicKey({
      key: spkiKey,
      format: 'der',
      type: 'spki',
    });

    return nodeCrypto.verify(null, Buffer.from(dataBytes), keyObject, Buffer.from(sigBytes));
  } catch (err) {
    return false;
  }
}

/**
 * Verifies an RSA-SHA256 signature using PEM public key/cert or DER bytes.
 */
export async function verifyRsaSha256(
  publicKeyOrCert: string | Uint8Array,
  signature: string | Uint8Array,
  data: string | Uint8Array
): Promise<boolean> {
  try {
    let sigBytes: Uint8Array;
    if (typeof signature === 'string') {
      const cleanSig = signature.trim();
      if (/^[0-9a-fA-F]+$/.test(cleanSig) && cleanSig.length % 2 === 0) {
        sigBytes = hexToBytes(cleanSig);
      } else {
        sigBytes = base64ToBytes(cleanSig);
      }
    } else {
      sigBytes = signature;
    }
    const dataBytes = typeof data === 'string' ? stringToBytes(data) : data;

    const cryptoSubtle = globalThis.crypto?.subtle;

    if (cryptoSubtle && typeof publicKeyOrCert === 'string' && !publicKeyOrCert.includes('-----BEGIN')) {
      const keyDer = base64ToBytes(publicKeyOrCert);
      const cryptoKey = await cryptoSubtle.importKey(
        'spki',
        keyDer as unknown as BufferSource,
        { name: 'RSASSSA-PKCS1-v1_5', hash: { name: 'SHA-256' } },
        false,
        ['verify']
      );

      return await cryptoSubtle.verify(
        'RSASSSA-PKCS1-v1_5',
        cryptoKey,
        sigBytes as unknown as BufferSource,
        dataBytes as unknown as BufferSource
      );
    }

    const nodeCrypto = await import('node:crypto');
    const verify = nodeCrypto.createVerify('RSA-SHA256');
    verify.update(Buffer.from(dataBytes));
    return verify.verify(publicKeyOrCert as any, Buffer.from(sigBytes));
  } catch (err) {
    return false;
  }
}
