import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { verifyWebhook } from 'verihook';

const app = new Hono();

app.get('/', (c) => {
  return c.json({
    name: 'verihook Hono / Cloudflare Workers example',
    routes: ['/webhook/:provider'],
  });
});

app.post('/webhook/:provider', async (c) => {
  const provider = c.req.param('provider');
  const secret = c.env?.WEBHOOK_SECRET || process.env.WEBHOOK_SECRET || 'secret123';

  // Pass Web Standard Fetch Request c.req.raw directly to verihook!
  const result = await verifyWebhook(provider, c.req.raw, secret);

  if (!result.valid) {
    return c.json({ error: result.reason }, 401);
  }

  const payload = await c.req.json();
  return c.json({
    success: true,
    provider: result.provider,
    timestamp: result.timestamp,
    payloadSummary: payload,
  });
});

const port = 3000;
console.log(`🚀 Hono verihook worker server running at http://localhost:${port}`);

serve({
  fetch: app.fetch,
  port,
});
