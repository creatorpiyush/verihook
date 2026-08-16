import { describe, expect, it } from "vitest";
import { runCli } from "../src/cli/index.js";

describe("SSRF Protection & URL Validation", () => {
  it("should block AWS / GCP / Azure metadata IPs (169.254.169.254)", async () => {
    await expect(
      runCli([
        "simulate",
        "stripe",
        "--url",
        "http://169.254.169.254/latest/meta-data",
        "--curl",
      ]),
    ).rejects.toThrow(/SSRF Prevention/);
  });

  it("should block 169.254.x.x link-local subnet IPs", async () => {
    await expect(
      runCli([
        "simulate",
        "stripe",
        "--url",
        "http://169.254.170.2/v2/metadata",
        "--curl",
      ]),
    ).rejects.toThrow(/SSRF Prevention/);
  });

  it("should block GCP metadata host (metadata.google.internal)", async () => {
    await expect(
      runCli([
        "simulate",
        "stripe",
        "--url",
        "http://metadata.google.internal/computeMetadata/v1/",
        "--curl",
      ]),
    ).rejects.toThrow(/SSRF Prevention/);
  });

  it("should block non-HTTP protocols (e.g. file://)", async () => {
    await expect(
      runCli(["simulate", "stripe", "--url", "file:///etc/passwd", "--curl"]),
    ).rejects.toThrow(/Forbidden URL protocol/);
  });

  it("should allow local requests to 0.0.0.0 or [::1] in simulation mode", async () => {
    await expect(
      runCli([
        "simulate",
        "stripe",
        "--url",
        "http://0.0.0.0:3000/webhooks/stripe",
        "--curl",
      ]),
    ).resolves.toBeUndefined();
  });
});
