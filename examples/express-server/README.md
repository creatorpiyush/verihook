# verihook Express Example Server

This example demonstrates how to verify incoming webhooks from **GitHub, Svix / Resend, Stripe, Slack, Linear, and custom services** using `verihook` in an Express application.

## Getting Started

1. **Install Dependencies**:
   ```bash
   cd examples/express-server
   npm install
   ```

2. **Copy Environment Variables**:
   ```bash
   cp .env.example .env
   ```

3. **Start Server**:
   ```bash
   npm run dev
   ```

The server will start at `http://localhost:3000`.

---

## Testing Local Webhooks with Free Webhook Generators

To test real webhooks live locally:

1. Use **[ngrok](https://ngrok.com)** or **[localtunnel](https://localtunnel.me)** to expose your server:
   ```bash
   npx localtunnel --port 3000
   # Gives you a public URL like https://happy-cat-88.loca.lt
   ```

2. Register webhooks on **free services**:
   - **GitHub Webhooks**: Repo Settings -> Webhooks -> Add Webhook (`https://your-url/webhooks/github`, secret).
   - **Svix Play**: Use [play.svix.com](https://play.svix.com) to simulate real Svix signed webhooks.
   - **Stripe Test Mode**: In Stripe Dashboard -> Developers -> Webhooks, add endpoint in Test mode (free).
