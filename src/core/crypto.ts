import { base64ToBytes, hexToBytes, stringToBytes } from "../utils/encoding.js";

/**
 * Perform constant-time comparison of two strings or Uint8Arrays to prevent timing attacks.
 */
export function timingSafeEqual(
  a: string | Uint8Array,
  b: string | Uint8Array,
): boolean {
  if (
    a === undefined ||
    a === null ||
    b === undefined ||
    b === null ||
    (typeof a !== "string" && !(a instanceof Uint8Array)) ||
    (typeof b !== "string" && !(b instanceof Uint8Array))
  ) {
    return false;
  }

  const bytesA = typeof a === "string" ? stringToBytes(a) : a;
  const bytesB = typeof b === "string" ? stringToBytes(b) : b;

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
  const bytes = typeof data === "string" ? stringToBytes(data) : data;
  let crc = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) {
    crc = CRC32_TABLE[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

/**
 * Computes a SHA-256 hash digest.
 */
export async function computeSha256(
  data: string | Uint8Array,
): Promise<Uint8Array> {
  const dataBytes = typeof data === "string" ? stringToBytes(data) : data;
  const cryptoSubtle = globalThis.crypto?.subtle;

  if (cryptoSubtle) {
    const hash = await cryptoSubtle.digest(
      "SHA-256",
      dataBytes as unknown as BufferSource,
    );
    return new Uint8Array(hash);
  }

  try {
    const nodeCrypto = await import("node:crypto");
    const hash = nodeCrypto.createHash("sha256");
    hash.update(Buffer.from(dataBytes));
    return new Uint8Array(hash.digest());
  } catch (err) {
    throw new Error("Crypto API unavailable for computing SHA-256 hash");
  }
}

/**
 * Computes an HMAC digest using Web Crypto API or Node crypto fallback.
 */
export async function computeHmac(
  algorithm: "SHA-256" | "SHA-1" | "SHA-512",
  secret: string | Uint8Array,
  data: string | Uint8Array,
): Promise<Uint8Array> {
  const secretBytes =
    typeof secret === "string" ? stringToBytes(secret) : secret;
  const dataBytes = typeof data === "string" ? stringToBytes(data) : data;

  const cryptoSubtle = globalThis.crypto?.subtle;

  if (cryptoSubtle) {
    const key = await cryptoSubtle.importKey(
      "raw",
      secretBytes as unknown as BufferSource,
      { name: "HMAC", hash: { name: algorithm } },
      false,
      ["sign"],
    );

    const signature = await cryptoSubtle.sign(
      "HMAC",
      key,
      dataBytes as unknown as BufferSource,
    );
    return new Uint8Array(signature);
  }

  try {
    const nodeCrypto = await import("node:crypto");
    const nodeAlg = algorithm.replace("-", "").toLowerCase();
    const hmac = nodeCrypto.createHmac(nodeAlg, Buffer.from(secretBytes));
    hmac.update(Buffer.from(dataBytes));
    return new Uint8Array(hmac.digest());
  } catch (err) {
    throw new Error(`Crypto API unavailable for computing HMAC ${algorithm}`);
  }
}

export function computeHmacSha256(
  secret: string | Uint8Array,
  data: string | Uint8Array,
): Promise<Uint8Array> {
  return computeHmac("SHA-256", secret, data);
}

export function computeHmacSha1(
  secret: string | Uint8Array,
  data: string | Uint8Array,
): Promise<Uint8Array> {
  return computeHmac("SHA-1", secret, data);
}

export function computeHmacSha512(
  secret: string | Uint8Array,
  data: string | Uint8Array,
): Promise<Uint8Array> {
  return computeHmac("SHA-512", secret, data);
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
  data: string | Uint8Array,
): Promise<boolean> {
  try {
    const pubBytes =
      typeof publicKey === "string" ? hexToBytes(publicKey) : publicKey;
    const sigBytes =
      typeof signature === "string" ? hexToBytes(signature) : signature;
    const dataBytes = typeof data === "string" ? stringToBytes(data) : data;

    if (pubBytes.length !== 32 || sigBytes.length !== 64) {
      return false;
    }

    const cryptoSubtle = globalThis.crypto?.subtle;

    if (cryptoSubtle) {
      const spkiKey = new Uint8Array(
        ED25519_SPKI_HEADER.length + pubBytes.length,
      );
      spkiKey.set(ED25519_SPKI_HEADER, 0);
      spkiKey.set(pubBytes, ED25519_SPKI_HEADER.length);

      const cryptoKey = await cryptoSubtle.importKey(
        "spki",
        spkiKey as unknown as BufferSource,
        { name: "Ed25519" },
        false,
        ["verify"],
      );

      return await cryptoSubtle.verify(
        { name: "Ed25519" },
        cryptoKey,
        sigBytes as unknown as BufferSource,
        dataBytes as unknown as BufferSource,
      );
    }

    const nodeCrypto = await import("node:crypto");
    const spkiKey = Buffer.concat([
      Buffer.from(ED25519_SPKI_HEADER),
      Buffer.from(pubBytes),
    ]);
    const keyObject = nodeCrypto.createPublicKey({
      key: spkiKey,
      format: "der",
      type: "spki",
    });

    return nodeCrypto.verify(
      null,
      Buffer.from(dataBytes),
      keyObject,
      Buffer.from(sigBytes),
    );
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
  data: string | Uint8Array,
): Promise<boolean> {
  try {
    let sigBytes: Uint8Array;
    if (typeof signature === "string") {
      const cleanSig = signature.trim();
      if (/^[0-9a-fA-F]+$/.test(cleanSig) && cleanSig.length % 2 === 0) {
        sigBytes = hexToBytes(cleanSig);
      } else {
        sigBytes = base64ToBytes(cleanSig);
      }
    } else {
      sigBytes = signature;
    }
    const dataBytes = typeof data === "string" ? stringToBytes(data) : data;

    const cryptoSubtle = globalThis.crypto?.subtle;

    if (
      cryptoSubtle &&
      typeof publicKeyOrCert === "string" &&
      !publicKeyOrCert.includes("-----BEGIN")
    ) {
      const keyDer = base64ToBytes(publicKeyOrCert);
      const cryptoKey = await cryptoSubtle.importKey(
        "spki",
        keyDer as unknown as BufferSource,
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        false,
        ["verify"],
      );

      return await cryptoSubtle.verify(
        "RSASSA-PKCS1-v1_5",
        cryptoKey,
        sigBytes as unknown as BufferSource,
        dataBytes as unknown as BufferSource,
      );
    }

    const nodeCrypto = await import("node:crypto");
    const verify = nodeCrypto.createVerify("RSA-SHA256");
    verify.update(Buffer.from(dataBytes));
    const key =
      typeof publicKeyOrCert === "string"
        ? publicKeyOrCert
        : Buffer.from(publicKeyOrCert);
    return verify.verify(key, Buffer.from(sigBytes));
  } catch (err) {
    return false;
  }
}

function readDerLength(
  bytes: Uint8Array,
  offset: number,
): [length: number, next: number] {
  const first = bytes[offset];
  if (first < 0x80) return [first, offset + 1];
  const count = first & 0x7f;
  if (count < 1 || count > 2) throw new Error("Unsupported DER length");
  let length = 0;
  for (let i = 1; i <= count; i++) length = (length << 8) | bytes[offset + i];
  return [length, offset + 1 + count];
}

/**
 * Converts a DER-encoded ECDSA signature (`SEQUENCE { r INTEGER, s INTEGER }`) into
 * the fixed-size `r || s` form Web Crypto expects.
 */
export function ecdsaDerToRaw(der: Uint8Array, size = 32): Uint8Array {
  if (der[0] !== 0x30) throw new Error("Invalid DER signature");
  let [, offset] = readDerLength(der, 1);
  const raw = new Uint8Array(size * 2);
  for (let part = 0; part < 2; part++) {
    if (der[offset] !== 0x02) throw new Error("Invalid DER integer");
    const [length, start] = readDerLength(der, offset + 1);
    let value = der.subarray(start, start + length);
    while (value.length > size && value[0] === 0) value = value.subarray(1);
    if (value.length > size) throw new Error("Invalid DER integer size");
    raw.set(value, part * size + (size - value.length));
    offset = start + length;
  }
  return raw;
}

/** Converts a fixed-size `r || s` ECDSA signature into DER. */
export function ecdsaRawToDer(raw: Uint8Array): Uint8Array {
  const size = raw.length / 2;
  const integer = (bytes: Uint8Array): number[] => {
    let start = 0;
    while (start < bytes.length - 1 && bytes[start] === 0) start++;
    const trimmed = Array.from(bytes.subarray(start));
    if (trimmed[0] & 0x80) trimmed.unshift(0);
    return [0x02, trimmed.length, ...trimmed];
  };
  const body = [
    ...integer(raw.subarray(0, size)),
    ...integer(raw.subarray(size)),
  ];
  return new Uint8Array([0x30, body.length, ...body]);
}

/**
 * Verifies an ECDSA P-256 / SHA-256 signature (as SendGrid sends).
 * `publicKey` is a base64 SPKI key or a PEM `PUBLIC KEY` block; `signature` is a
 * base64 DER signature.
 */
export async function verifyEcdsaP256Sha256(
  publicKey: string,
  signature: string,
  data: string | Uint8Array,
): Promise<boolean> {
  try {
    const keyDer = base64ToBytes(
      publicKey
        .replace(/-----(BEGIN|END) PUBLIC KEY-----/g, "")
        .replace(/\s+/g, ""),
    );
    const sigDer = base64ToBytes(signature.trim());
    const dataBytes = typeof data === "string" ? stringToBytes(data) : data;

    const cryptoSubtle = globalThis.crypto?.subtle;
    if (cryptoSubtle) {
      const cryptoKey = await cryptoSubtle.importKey(
        "spki",
        keyDer as unknown as BufferSource,
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["verify"],
      );
      return await cryptoSubtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        cryptoKey,
        ecdsaDerToRaw(sigDer) as unknown as BufferSource,
        dataBytes as unknown as BufferSource,
      );
    }

    const nodeCrypto = await import("node:crypto");
    const keyObject = nodeCrypto.createPublicKey({
      key: Buffer.from(keyDer),
      format: "der",
      type: "spki",
    });
    return nodeCrypto.verify(
      "sha256",
      Buffer.from(dataBytes),
      { key: keyObject, dsaEncoding: "der" },
      Buffer.from(sigDer),
    );
  } catch {
    return false;
  }
}
