import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { verihookHono, type VerihookVariables } from 'verihook/hono';

type Env = {
  Bindings: { WEBHOOK_SECRET?: string };
  Variables: VerihookVariables;
};

const app = new Hono<Env>();

// On Cloudflare Workers the secret comes from c.env. Locally it falls back to process.env.
const secret = (c: { env?: Env['Bindings'] }) =>
  c.env?.WEBHOOK_SECRET || process.env.WEBHOOK_SECRET || 'secret123';

app.get('/', (c) => {
  return c.json({
    name: 'verihook Hono / Cloudflare Workers example',
    routes: ['/webhook/stripe', '/webhook/github', '/webhook/shopify'],
  });
});

for (const provider of ['stripe', 'github', 'shopify'] as const) {
  // Invalid signatures get a 401 before the handler runs.
  app.post(`/webhook/${provider}`, verihookHono(provider, secret), (c) => {
    const { eventType, timestamp, event } = c.get('verihook');
    return c.json({
      success: true,
      provider,
      eventType,
      timestamp,
      payloadSummary: event,
    });
  });
}

const port = 3000;
console.log(`🚀 Hono verihook worker server running at http://localhost:${port}`);

serve({
  fetch: app.fetch,
  port,
});
