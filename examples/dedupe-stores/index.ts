import { verifyWebhook } from "verihook";
import { UpstashDedupeStore } from "./upstash-redis.js";
import { CloudflareKVDedupeStore } from "./cloudflare-kv.js";

async function main() {
  console.log("Initializing UpstashDedupeStore example...");
  const upstashStore = new UpstashDedupeStore();

  console.log("Dedupe store created successfully.");
  console.log("CloudflareKVDedupeStore and UpstashDedupeStore ready for use.");
}

main().catch(console.error);
