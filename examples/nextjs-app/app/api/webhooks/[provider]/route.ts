import { NextResponse } from 'next/server';
import { verifyWebhook } from 'verihook';

export async function POST(
  req: Request,
  { params }: { params: Promise<{ provider: string }> }
) {
  // Next.js 15+ passes route params as a Promise.
  const { provider } = await params;

  // Retrieve environment secret corresponding to the provider
  const envKey = `${provider.toUpperCase()}_WEBHOOK_SECRET`;
  const secret = process.env[envKey] || process.env.WEBHOOK_SECRET || 'default_secret';

  // Verify incoming webhook request using verihook
  const result = await verifyWebhook(provider, req, secret);

  if (!result.valid) {
    console.error(`❌ [Next.js Webhook] ${provider} verification failed:`, result.reason);
    return NextResponse.json({ error: result.reason }, { status: 401 });
  }

  // The verified, parsed payload
  console.log(`✅ [Next.js Webhook] ${provider} verified successfully:`, result.event);

  return NextResponse.json({
    success: true,
    provider: result.provider,
    timestamp: result.timestamp,
  });
}
