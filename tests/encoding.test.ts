import { describe, expect, it } from "vitest";
import {
  base64ToBytes,
  bytesToBase64,
  bytesToHex,
  bytesToString,
  hexToBytes,
  stringToBytes,
} from "../src/utils/encoding.js";

describe("Encoding Utilities", () => {
  it("should convert strings to bytes and back", () => {
    const original = "Verihook Webhook Verifier ✨";
    const bytes = stringToBytes(original);
    const decoded = bytesToString(bytes);
    expect(decoded).toBe(original);
  });

  it("should convert bytes to hex and back", () => {
    const bytes = new Uint8Array([0, 15, 255, 128, 64]);
    const hex = bytesToHex(bytes);
    expect(hex).toBe("000fff8040");
    const decodedBytes = hexToBytes(hex);
    expect(decodedBytes).toEqual(bytes);
  });

  it("should throw error on invalid odd-length hex string", () => {
    expect(() => hexToBytes("abc")).toThrow("Invalid hex string length");
  });

  it("should convert bytes to base64 and back in Buffer environment", () => {
    const bytes = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
    const b64 = bytesToBase64(bytes);
    expect(b64).toBe("SGVsbG8=");
    const decodedBytes = base64ToBytes(b64);
    expect(decodedBytes).toEqual(bytes);
  });

  it("should convert bytes to base64 and back in non-Buffer environment (btoa/atob fallback)", () => {
    const originalBuffer = globalThis.Buffer;
    try {
      (globalThis as any).Buffer = undefined;

      const bytes = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
      const b64 = bytesToBase64(bytes);
      expect(b64).toBe("SGVsbG8=");
      const decodedBytes = base64ToBytes(b64);
      expect(decodedBytes).toEqual(bytes);
    } finally {
      (globalThis as any).Buffer = originalBuffer;
    }
  });

  it("should throw error on invalid base64 string format", () => {
    expect(() => base64ToBytes("invalid_b64!!!")).toThrow(
      "Invalid base64 string",
    );
  });
});
