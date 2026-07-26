import Fastify from 'fastify';
import { verifyWebhook } from 'verihook';

const fastify = Fastify({ logger: true });

// Capture raw body string for Webhook signature verification
fastify.addContentTypeParser('*', { parseAs: 'string' }, (_req, body, done) => {
  done(null, body);
});

fastify.post('/webhooks/:provider', async (request, reply) => {
  const { provider } = request.params as { provider: string };
  const secret = process.env.WEBHOOK_SECRET || 'secret123';

  // Pass Fastify request directly to verihook
  const result = await verifyWebhook(provider, {
    headers: request.headers as Record<string, string>,
    rawBody: request.body as string,
    url: request.url,
  }, secret);

  if (!result.valid) {
    return reply.status(401).send({ error: result.reason });
  }

  const payload = JSON.parse(request.body as string);
  return reply.send({
    success: true,
    provider: result.provider,
    payload,
  });
});

const start = async () => {
  try {
    await fastify.listen({ port: 3000 });
    console.log('🚀 Fastify verihook server listening on http://localhost:3000');
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();
