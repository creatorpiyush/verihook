# verihook Fastify Example

This example verifies webhooks in **Fastify** with `verihook/fastify`:

- `verihookRawBody` keeps `request.rawBody`, the exact bytes the provider signed. It still parses JSON and form bodies into `request.body`.
- `verihookFastify(provider, secret)` is a `preHandler` hook. Invalid signatures get a 401 and duplicates a 200 before your handler runs. Verified routes see `request.verihook`.

## Running Locally

```bash
cd examples/fastify-server
npm install
npm run dev

# In another terminal, send a signed test webhook:
npx verihook simulate stripe --secret secret123 --url http://localhost:3000/webhooks/stripe
```

Server runs on `http://localhost:3000`, with routes `/webhooks/stripe`, `/webhooks/github`, `/webhooks/shopify` and `/webhooks/slack`.
