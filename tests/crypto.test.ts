import { describe, expect, it } from "vitest";
import crypto from "node:crypto";
import {
  computeHmac,
  computeHmacSha1,
  computeHmacSha256,
  computeHmacSha512,
  computeSha256,
  timingSafeEqual,
  verifyEd25519,
  verifyRsaSha256,
} from "../src/core/crypto.js";
import { bytesToHex, stringToBytes } from "../src/utils/encoding.js";

describe("Crypto Utilities & Constant Time Comparison", () => {
  it("should return true for identical strings and bytes", () => {
    expect(timingSafeEqual("secret123", "secret123")).toBe(true);
    expect(timingSafeEqual(stringToBytes("test"), stringToBytes("test"))).toBe(
      true,
    );
  });

  it("should return false for unequal strings or different byte lengths", () => {
    expect(timingSafeEqual("secret123", "secret124")).toBe(false);
    expect(timingSafeEqual("secret123", "secret1234")).toBe(false);
    expect(
      timingSafeEqual(stringToBytes("short"), stringToBytes("longer_string")),
    ).toBe(false);
  });

  it("should compute accurate SHA-256 hash digest", async () => {
    const hashBytes = await computeSha256("hello world");
    const hashHex = bytesToHex(hashBytes);
    expect(hashHex).toBe(
      "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
    );
  });

  it("should compute HMAC SHA-256 digest", async () => {
    const hmacBytes = await computeHmacSha256("secret", "message");
    const hex = bytesToHex(hmacBytes);
    expect(hex).toBe(
      "8b5f48702995c1598c573db1e21866a9b825d4a794d169d7060a03605796360b",
    );
  });

  it("should compute HMAC SHA-1 digest", async () => {
    const hmacBytes = await computeHmacSha1("secret", "message");
    const hex = bytesToHex(hmacBytes);
    expect(hex.length).toBe(40);
  });

  it("should compute HMAC SHA-512 digest", async () => {
    const hmacBytes = await computeHmacSha512("secret", "message");
    const hex = bytesToHex(hmacBytes);
    expect(hex.length).toBe(128);
  });

  it("should compute generic HMAC with sha256 algorithm", async () => {
    const hmacBytes = await computeHmac("SHA-256", "secret", "message");
    const hex = bytesToHex(hmacBytes);
    expect(hex).toBe(
      "8b5f48702995c1598c573db1e21866a9b825d4a794d169d7060a03605796360b",
    );
  });

  it("should verify Ed25519 signature in both WebCrypto and Node fallback modes", async () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
    const spkiDer = publicKey.export({ type: "spki", format: "der" });
    const rawPubKey = spkiDer.subarray(spkiDer.length - 32);

    const dataStr = "payload_to_verify_ed25519";
    const sigBytes = crypto.sign(null, Buffer.from(dataStr), privateKey);

    const resWebCrypto = await verifyEd25519(rawPubKey, sigBytes, dataStr);
    expect(resWebCrypto).toBe(true);

    const origSubtle = globalThis.crypto?.subtle;
    try {
      Object.defineProperty(globalThis.crypto, "subtle", {
        value: undefined,
        configurable: true,
        writable: true,
      });
      const resNode = await verifyEd25519(rawPubKey, sigBytes, dataStr);
      expect(resNode).toBe(true);
    } finally {
      Object.defineProperty(globalThis.crypto, "subtle", {
        value: origSubtle,
        configurable: true,
        writable: true,
      });
    }
  });

  it("should verify RSA-SHA256 signature with PEM public key and hex signature", async () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
    });
    const pemPubKey = publicKey
      .export({ type: "pkcs1", format: "pem" })
      .toString();

    const dataStr = "payload_to_verify_rsa";
    const signer = crypto.createSign("RSA-SHA256");
    signer.update(dataStr);
    const sigBytes = signer.sign(privateKey);
    const sigHex = bytesToHex(sigBytes);

    const res = await verifyRsaSha256(pemPubKey, sigHex, dataStr);
    expect(res).toBe(true);

    const resUint8 = await verifyRsaSha256(pemPubKey, sigBytes, dataStr);
    expect(resUint8).toBe(true);
  });

  it("should fallback to Node crypto when globalThis.crypto.subtle is undefined", async () => {
    const origSubtle = globalThis.crypto?.subtle;
    try {
      Object.defineProperty(globalThis.crypto, "subtle", {
        value: undefined,
        configurable: true,
        writable: true,
      });

      const hash = await computeSha256("hello world");
      expect(bytesToHex(hash)).toBe(
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
      );

      const hmac = await computeHmacSha256("secret", "message");
      expect(bytesToHex(hmac)).toBe(
        "8b5f48702995c1598c573db1e21866a9b825d4a794d169d7060a03605796360b",
      );
    } finally {
      Object.defineProperty(globalThis.crypto, "subtle", {
        value: origSubtle,
        configurable: true,
        writable: true,
      });
    }
  });

  it("should reject invalid Ed25519 public key or signature lengths", async () => {
    const invalidPub = "1234";
    const invalidSig = "5678";
    const result = await verifyEd25519(invalidPub, invalidSig, "payload");
    expect(result).toBe(false);
  });
});
