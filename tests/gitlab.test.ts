import { describe, expect, it } from "vitest";
import { MemoryDedupeStore, verifyGitLab } from "../src/index.js";
import { signWebhook } from "../src/testing.js";

describe("GitLab Webhook Verifier", () => {
  describe("signing token (Standard Webhooks)", () => {
    // Published Standard Webhooks / Svix test vector.
    const secret = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
    const body = '{"test": 2432232314}';
    const headers = {
      "webhook-id": "msg_p5jXN8AQM9LWM0D4loKWxJek",
      "webhook-timestamp": "1614265330",
      "webhook-signature": "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=",
      "x-gitlab-event": "Push Hook",
    };
    const now = 1614265330;

    it("verifies the published test vector", async () => {
      const result = await verifyGitLab({ headers, body }, secret, { now });
      expect(result.valid).toBe(true);
      expect(result.provider).toBe("gitlab");
      expect(result.timestamp).toBe(now);
      expect(result.eventType).toBe("Push Hook");
    });

    it("rejects a wrong token, a modified body and an expired timestamp", async () => {
      expect(
        (await verifyGitLab({ headers, body }, "whsec_b3RoZXI=", { now })).code,
      ).toBe("INVALID_SIGNATURE");
      expect(
        (await verifyGitLab({ headers, body: '{"test": 1}' }, secret, { now }))
          .code,
      ).toBe("INVALID_SIGNATURE");
      expect(
        (await verifyGitLab({ headers, body }, secret, { now: now + 301 }))
          .code,
      ).toBe("EXPIRED_TIMESTAMP");
    });

    it("reports missing Standard Webhooks headers", async () => {
      const result = await verifyGitLab(
        {
          headers: { "webhook-signature": headers["webhook-signature"] },
          body,
        },
        secret,
      );
      expect(result.code).toBe("MISSING_HEADER");
      expect(result.reason).toContain("webhook-id");
    });

    it("round-trips signWebhook and dedupes on webhook-id", async () => {
      const hook = await signWebhook("gitlab", {
        secret,
        payload: { object_kind: "merge_request" },
      });
      expect(hook.headers["webhook-signature"]).toMatch(/^v1,/);
      expect(hook.headers["x-gitlab-token"]).toBeUndefined();
      const dedupeStore = new MemoryDedupeStore();
      const first = await verifyGitLab(hook, secret, { dedupeStore });
      expect(first.valid).toBe(true);
      expect(first.eventType).toBe("merge_request");
      expect(first.dedupeKey).toContain(hook.headers["webhook-id"]);
    });
  });

  describe("secret token (legacy)", () => {
    const secret = "gitlab-token-123";
    const body =
      '{"object_kind":"push","ref":"refs/heads/main","project":{"id":1,"path_with_namespace":"group/project"}}';

    it("accepts the matching token", async () => {
      const result = await verifyGitLab(
        {
          headers: { "X-Gitlab-Token": secret, "X-Gitlab-Event": "Push Hook" },
          body,
        },
        secret,
      );
      expect(result.valid).toBe(true);
      expect(result.eventType).toBe("push");
      expect(result.event?.project?.path_with_namespace).toBe("group/project");
    });

    it("rejects a wrong token and a missing header", async () => {
      expect(
        (
          await verifyGitLab(
            { headers: { "x-gitlab-token": "nope" }, body },
            secret,
          )
        ).code,
      ).toBe("INVALID_SIGNATURE");
      expect((await verifyGitLab({ headers: {}, body }, secret)).code).toBe(
        "MISSING_HEADER",
      );
    });

    it("dedupes on idempotency-key", async () => {
      const dedupeStore = new MemoryDedupeStore();
      const req = {
        headers: { "x-gitlab-token": secret, "idempotency-key": "idem-1" },
        body,
      };
      expect((await verifyGitLab(req, secret, { dedupeStore })).valid).toBe(
        true,
      );
      expect((await verifyGitLab(req, secret, { dedupeStore })).code).toBe(
        "DUPLICATE_EVENT",
      );
    });

    it("round-trips signWebhook", async () => {
      const hook = await signWebhook("gitlab", {
        secret,
        event: "Tag Push Hook",
      });
      expect(hook.headers["x-gitlab-token"]).toBe(secret);
      const result = await verifyGitLab(hook, secret);
      expect(result.valid).toBe(true);
      expect(result.eventType).toBe("Tag Push Hook");
    });
  });
});
