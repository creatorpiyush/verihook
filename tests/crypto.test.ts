import { describe, expect, it } from 'vitest';
import {
  computeHmac,
  computeHmacSha1,
  computeHmacSha256,
  computeHmacSha512,
  computeSha256,
  timingSafeEqual,
} from '../src/core/crypto.js';
import { bytesToHex, stringToBytes } from '../src/utils/encoding.js';

describe('Crypto Utilities & Constant Time Comparison', () => {
  it('should return true for identical strings and bytes', () => {
    expect(timingSafeEqual('secret123', 'secret123')).toBe(true);
    expect(timingSafeEqual(stringToBytes('test'), stringToBytes('test'))).toBe(true);
  });

  it('should return false for unequal strings or different byte lengths', () => {
    expect(timingSafeEqual('secret123', 'secret124')).toBe(false);
    expect(timingSafeEqual('secret123', 'secret1234')).toBe(false);
    expect(timingSafeEqual(stringToBytes('short'), stringToBytes('longer_string'))).toBe(false);
  });

  it('should compute accurate SHA-256 hash digest', async () => {
    const hashBytes = await computeSha256('hello world');
    const hashHex = bytesToHex(hashBytes);
    // RFC test vector: SHA256("hello world") = b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
    expect(hashHex).toBe('b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9');
  });

  it('should compute HMAC SHA-256 digest', async () => {
    const hmacBytes = await computeHmacSha256('secret', 'message');
    const hex = bytesToHex(hmacBytes);
    // HMAC-SHA256("secret", "message") = 8b5f48702995c1598c573db1e21866a9b825d4a794d9c7b3893e9177842b665b
    expect(hex).toBe('8b5f48702995c1598c573db1e21866a9b825d4a794d169d7060a03605796360b');
  });

  it('should compute HMAC SHA-1 digest', async () => {
    const hmacBytes = await computeHmacSha1('secret', 'message');
    const hex = bytesToHex(hmacBytes);
    expect(hex.length).toBe(40); // 20 bytes = 40 hex chars
  });

  it('should compute HMAC SHA-512 digest', async () => {
    const hmacBytes = await computeHmacSha512('secret', 'message');
    const hex = bytesToHex(hmacBytes);
    expect(hex.length).toBe(128); // 64 bytes = 128 hex chars
  });

  it('should compute generic HMAC with sha256 algorithm', async () => {
    const hmacBytes = await computeHmac('SHA-256', 'secret', 'message');
    const hex = bytesToHex(hmacBytes);
    expect(hex).toBe('8b5f48702995c1598c573db1e21866a9b825d4a794d169d7060a03605796360b');
  });
});
