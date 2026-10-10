import { describe, expect, it } from "vitest";
import { isNonPublicHost } from "../src/utils/ssrf.js";

const host = (url: string) => new URL(url).hostname;

describe("isNonPublicHost", () => {
  it.each([
    "http://localhost/",
    "http://LOCALHOST./",
    "http://api.localhost/",
    "http://127.0.0.1/",
    "http://0x7f000001/",
    "http://2130706433/",
    "http://0177.0.0.1/",
    "http://0.0.0.0/",
    "http://10.1.2.3/",
    "http://172.20.0.1/",
    "http://192.168.1.1/",
    "http://100.64.0.1/",
    "http://169.254.169.254/latest/meta-data",
    "http://metadata.google.internal/",
    "http://224.0.0.1/",
    "http://[::1]/",
    "http://[::]/",
    "http://[0:0:0:0:0:0:0:1]/",
    "http://[fd00::1]/",
    "http://[fc12:3456::1]/",
    "http://[fe80::1]/",
    "http://[::ffff:127.0.0.1]/",
    "http://[::ffff:10.0.0.1]/",
    "http://[::ffff:169.254.169.254]/",
  ])("blocks %s", (url) => {
    expect(isNonPublicHost(host(url))).toBe(true);
  });

  it.each([
    "https://example.com/hooks",
    "https://8.8.8.8/",
    "https://172.32.0.1/",
    "https://[2606:4700:4700::1111]/",
    "https://[::ffff:8.8.8.8]/",
    "https://fd.example.com/",
  ])("allows %s", (url) => {
    expect(isNonPublicHost(host(url))).toBe(false);
  });
});
