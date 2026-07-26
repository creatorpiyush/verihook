# verihook Next.js (App Router) Example

This example demonstrates how to verify incoming webhooks natively in **Next.js 13+ App Router** using `verihook`.

## Features
- Dynamic route handler `/api/webhooks/[provider]` handling Stripe, GitHub, Shopify, Slack, Svix, etc.
- Works on Edge Runtime (`export const runtime = 'edge'`) and Node.js Serverless runtime.

## Running Locally

1. Install dependencies:
   ```bash
   cd examples/nextjs-app
   npm install
   ```

2. Copy env template:
   ```bash
   cp .env.example .env.local
   ```

3. Start dev server:
   ```bash
   npm run dev
   ```

Test endpoints at `http://localhost:3000/api/webhooks/github`, `http://localhost:3000/api/webhooks/stripe`, etc.
