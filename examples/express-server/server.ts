import dotenv from 'dotenv';
import express, { Request, Response } from 'express';
import { verifyWebhook, verifyWebhookOrThrow } from 'verihook';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// IMPORTANT: Webhook signature verification requires the raw, unparsed request body.
app.use(express.raw({ type: '*/*' }));

// Health Check Endpoint
app.get('/', (_req: Request, res: Response) => {
  res.json({
    status: 'online',
    message: 'verihook Example Webhook Server is running!',
    endpoints: [
      'POST /webhooks/github',
      'POST /webhooks/svix',
      'POST /webhooks/stripe',
      'POST /webhooks/slack',
      'POST /webhooks/linear',
      'POST /webhooks/generic',
    ],
  });
});

/**
 * 1. GitHub Webhook Handler
 */
app.post('/webhooks/github', async (req: Request, res: Response) => {
  const secret = process.env.GITHUB_WEBHOOK_SECRET || 'github_secret_123';

  const result = await verifyWebhook('github', req, secret);

  if (!result.valid) {
    console.error('❌ [GitHub] Webhook verification failed:', result.reason);
    return res.status(401).json({ error: result.reason });
  }

  const payload = JSON.parse(req.body.toString('utf-8'));
  console.log('✅ [GitHub] Verified event:', req.headers['x-github-event'], 'Action:', payload.action);

  res.status(200).json({ received: true });
});

/**
 * 2. Svix / Resend / Clerk Webhook Handler
 */
app.post('/webhooks/svix', async (req: Request, res: Response) => {
  const secret = process.env.SVIX_WEBHOOK_SECRET || 'whsec_MfKQ9r8GKY2ly3ShZsKm7zpAKGJikF3g';

  const result = await verifyWebhook('svix', req, secret);

  if (!result.valid) {
    console.error('❌ [Svix] Webhook verification failed:', result.reason);
    return res.status(401).json({ error: result.reason });
  }

  const payload = JSON.parse(req.body.toString('utf-8'));
  console.log('✅ [Svix] Verified event:', payload.type);

  res.status(200).json({ received: true });
});

import { verihookExpress } from 'verihook/express';
// Note: Can also be imported from 'verihook'

/**
 * 3. Stripe Webhook Handler (using 1-line verihookExpress middleware)
 */
app.post(
  '/webhooks/stripe',
  verihookExpress('stripe', process.env.STRIPE_WEBHOOK_SECRET || 'whsec_stripe_secret_123'),
  (req: any, res: Response) => {
    // req.verifiedPayload and req.verihook are guaranteed valid and payload parsed!
    const payload = req.verifiedPayload;
    console.log('✅ [Stripe] Verified event type via verihookExpress:', payload.type);
    console.log('📦 Stripe Event Payload Data:', payload.data?.object);
    res.status(200).json({ received: true });
  }
);

/**
 * 4. Slack Webhook Handler
 */
app.post('/webhooks/slack', async (req: Request, res: Response) => {
  const secret = process.env.SLACK_SIGNING_SECRET || 'slack_secret_123';

  const result = await verifyWebhook('slack', req, secret);

  if (!result.valid) {
    console.error('❌ [Slack] Webhook verification failed:', result.reason);
    return res.status(401).json({ error: result.reason });
  }

  const payloadStr = req.body.toString('utf-8');
  console.log('✅ [Slack] Verified request timestamp:', result.timestamp);

  res.status(200).json({ received: true });
});

/**
 * 5. Linear Webhook Handler
 */
app.post('/webhooks/linear', async (req: Request, res: Response) => {
  const secret = process.env.LINEAR_WEBHOOK_SECRET || 'linear_secret_123';

  const result = await verifyWebhook('linear', req, secret);

  if (!result.valid) {
    console.error('❌ [Linear] Webhook verification failed:', result.reason);
    return res.status(401).json({ error: result.reason });
  }

  const payload = JSON.parse(req.body.toString('utf-8'));
  console.log('✅ [Linear] Verified event action:', payload.action, 'type:', payload.type);

  res.status(200).json({ received: true });
});

/**
 * 6. Generic Custom Webhook Handler
 */
app.post('/webhooks/generic', async (req: Request, res: Response) => {
  const secret = process.env.GENERIC_WEBHOOK_SECRET || 'custom_secret_123';

  const result = await verifyWebhook('generic', req, secret, {
    headerName: 'x-custom-signature',
    algorithm: 'sha256',
    encoding: 'hex',
  });

  if (!result.valid) {
    console.error('❌ [Generic] Webhook verification failed:', result.reason);
    return res.status(401).json({ error: result.reason });
  }

  console.log('✅ [Generic] Verified custom webhook');
  res.status(200).json({ received: true });
});

app.listen(PORT, () => {
  console.log(`🚀 Verihook example server listening on http://localhost:${PORT}`);
});
