# verihook Hono / Cloudflare Workers Example

This example demonstrates how to use `verihook` in **Hono**, **Cloudflare Workers**, **Deno**, or **Bun**.

## How It Works
Hono uses standard Web Fetch API `Request` objects (`c.req.raw`). `verihook` passes `c.req.raw` directly into the Web Crypto API verifier with zero extra code!

## Running Locally

```bash
cd examples/hono-worker
npm install
npm run dev
```

Server runs on `http://localhost:3000`.
