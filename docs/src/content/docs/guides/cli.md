---
title: CLI
description: Send signed test webhooks to your local server with npx verihook simulate, and inspect live webhooks with the verihook listen relay.
sidebar:
  order: 6
---

The `verihook` CLI comes with the package. Run it with `npx verihook`.

## simulate

Sends a correctly signed webhook to your server, with no provider account needed:

```sh
npx verihook simulate stripe --url http://localhost:3000/webhooks/stripe
npx verihook simulate github --event issues
npx verihook simulate whatsapp --secret meta_app_secret
npx verihook simulate stripe --curl    # print a curl command instead
```

## listen

Runs a local relay that verifies each incoming webhook, prints its headers and body, and forwards it to your app:

```sh
npx verihook listen stripe --forward-to http://localhost:3000/webhooks/stripe --secret whsec_...
npx verihook listen github -p 8080 --forward-to http://localhost:4000/api/github
```

Point a tunnel (ngrok, Cloudflare Tunnel) or the provider's own forwarding tool at the relay's port.

## Options

| Option | Description |
| :--- | :--- |
| `--url <url>` | Where `simulate` sends the webhook. |
| `--forward-to <url>` | Where `listen` forwards verified webhooks. |
| `-p, --port <port>` | Port for `listen` (default 8080). |
| `--secret <key>` | Signing secret. |
| `--event <type>` | Event name, e.g. GitHub's `x-github-event`. |
| `--curl` | Print a curl command instead of sending. |
| `--allow-remote` | Allow non-local targets. |

## Safety

- Without `--allow-remote` (or `VERIHOOK_ALLOW_REMOTE=true`), the CLI warns before sending to non-local hosts.
- Cloud metadata endpoints, link-local addresses and their alternative encodings are blocked, as are non-HTTP protocols. This is defense in depth, not a substitute for network isolation.
- Secrets and signature headers are redacted in the terminal output.
