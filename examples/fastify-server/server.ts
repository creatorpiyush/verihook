import Fastify from 'fastify';
import { MemoryDedupeStore } from 'verihook';
import { verihookFastify, verihookRawBody, type VerihookFastifyRequest } from 'verihook/fastify';

const fastify = Fastify({ logger: true });
const dedupeStore = new MemoryDedupeStore();

// Keep the raw body for signature verification. JSON and form bodies are still parsed into request.body.
await fastify.register(verihookRawBody);

for (const provider of ['stripe', 'github', 'shopify', 'slack'] as const) {
  const secret = process.env[`${provider.toUpperCase()}_WEBHOOK_SECRET`] || process.env.WEBHOOK_SECRET || 'secret123';

  fastify.post(
    `/webhooks/${provider}`,
    // Invalid signatures get a 401 and duplicates a 200 before the handler runs.
    { preHandler: verihookFastify(provider, secret, { dedupeStore }) },
    async (request) => {
      const { eventType, event } = (request as typeof request & VerihookFastifyRequest).verihook!;
      request.log.info({ provider, eventType }, 'verified webhook');
      return { success: true, provider, eventType, payload: event };
    },
  );
}

try {
  await fastify.listen({ port: 3000 });
  console.log('🚀 Fastify verihook server listening on http://localhost:3000');
} catch (err) {
  fastify.log.error(err);
  process.exit(1);
}
