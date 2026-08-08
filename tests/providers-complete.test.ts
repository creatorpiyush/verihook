import { describe, expect, it } from "vitest";
import {
  verifyDiscord,
  verifyGitHub,
  verifyLinear,
  verifyMeta,
  verifyMetaChallenge,
  verifyPaddle,
  verifyPagerDuty,
  verifyRazorpay,
  verifySlack,
  verifySquare,
  verifyStripe,
  verifySvix,
  verifyWebflow,
  verifyWorkOS,
  verifyZoom,
} from "../src/index.js";

describe("Comprehensive Provider Edge Cases & Negative Paths", () => {
  const bodyStr = JSON.stringify({ event: "test_evt" });

  it("should cover Meta signature missing header and empty challenge query", async () => {
    const resSig = await verifyMeta({ headers: {}, body: bodyStr }, "sec");
    expect(resSig.valid).toBe(false);
    expect(resSig.code).toBe("MISSING_HEADER");

    const resChallenge = verifyMetaChallenge({}, "token");
    expect(resChallenge.valid).toBe(false);
    expect(resChallenge.reason).toContain("Invalid hub.mode");
  });

  it("should cover Paddle header formats, missing headers, and invalid sig", async () => {
    const missingRes = await verifyPaddle(
      { headers: {}, body: bodyStr },
      "sec",
    );
    expect(missingRes.valid).toBe(false);
    expect(missingRes.code).toBe("MISSING_HEADER");

    const invalidHeaderRes = await verifyPaddle(
      { headers: { "paddle-signature": "invalid_format" }, body: bodyStr },
      "sec",
    );
    expect(invalidHeaderRes.valid).toBe(false);
  });

  it("should cover WorkOS missing headers and invalid signature formatting", async () => {
    const missingRes = await verifyWorkOS(
      { headers: {}, body: bodyStr },
      "sec",
    );
    expect(missingRes.valid).toBe(false);

    const invalidHeaderRes = await verifyWorkOS(
      { headers: { "workos-signature": "invalid_format" }, body: bodyStr },
      "sec",
    );
    expect(invalidHeaderRes.valid).toBe(false);
  });

  it("should cover Svix missing headers and version fallback", async () => {
    const missingRes = await verifySvix({ headers: {}, body: bodyStr }, "sec");
    expect(missingRes.valid).toBe(false);

    const invalidSigRes = await verifySvix(
      {
        headers: {
          "svix-id": "msg_1",
          "svix-timestamp": String(Math.floor(Date.now() / 1000)),
          "svix-signature": "v2,invalid_v2_sig",
        },
        body: bodyStr,
      },
      "whsec_dGVzdF9zZWNyZXRfa2V5X2Zvcl9zdml4XzEyMw==",
    );
    expect(invalidSigRes.valid).toBe(false);
  });

  it("should cover Discord, Zoom, GitHub, Slack, Stripe, Webflow, Linear, Razorpay, Square missing headers", async () => {
    expect(
      (await verifyDiscord({ headers: {}, body: bodyStr }, "sec")).code,
    ).toBe("MISSING_HEADER");
    expect((await verifyZoom({ headers: {}, body: bodyStr }, "sec")).code).toBe(
      "MISSING_HEADER",
    );
    expect(
      (await verifyGitHub({ headers: {}, body: bodyStr }, "sec")).code,
    ).toBe("MISSING_HEADER");
    expect(
      (await verifySlack({ headers: {}, body: bodyStr }, "sec")).code,
    ).toBe("MISSING_HEADER");
    expect(
      (await verifyStripe({ headers: {}, body: bodyStr }, "sec")).code,
    ).toBe("MISSING_HEADER");
    expect(
      (await verifyWebflow({ headers: {}, body: bodyStr }, "sec")).code,
    ).toBe("MISSING_HEADER");
    expect(
      (await verifyLinear({ headers: {}, body: bodyStr }, "sec")).code,
    ).toBe("MISSING_HEADER");
    expect(
      (await verifyRazorpay({ headers: {}, body: bodyStr }, "sec")).code,
    ).toBe("MISSING_HEADER");
    expect(
      (await verifySquare({ headers: {}, body: bodyStr }, "sec")).code,
    ).toBe("MISSING_HEADER");
    expect(
      (await verifyPagerDuty({ headers: {}, body: bodyStr }, "sec")).code,
    ).toBe("MISSING_HEADER");
  });
});
