# verihook Hono / Cloudflare Workers Example

This example uses `verihook/hono` in **Hono**, which also covers **Cloudflare Workers**, **Deno** and **Bun**.

## How It Works
`verihookHono(provider, secret)` is a Hono middleware:

- It verifies a clone of `c.req.raw`, so the body stays readable (`c.req.json()` still works).
- Invalid signatures get a 401 before your handler runs.
- Verified requests get `c.get('verihook')`, with `event`, `eventType`, `timestamp` and the full `result`.

The secret can be a function of the context, e.g. `(c) => c.env.WEBHOOK_SECRET` on Workers.

## Running Locally

```bash
cd examples/hono-worker
npm install
npm run dev

# In another terminal, send a signed test webhook:
npx verihook simulate stripe --secret secret123 --url http://localhost:3000/webhook/stripe
```

Server runs on `http://localhost:3000`.
