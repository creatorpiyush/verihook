/**
 * Writes one page per provider (src/content/docs/providers/<id>.mdx) from
 * src/data/providers.mjs. The output is generated, so edit the data file instead.
 */
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { providers } from "../src/data/providers.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const outDir = join(root, "src/content/docs/providers");

const code = (lang, body) => `\`\`\`${lang}\n${body.trim()}\n\`\`\``;

function frameworkSnippets(p) {
  const secret = `process.env.${p.env}!`;
  const id = p.id;
  return [
    [
      "Next.js",
      `// app/api/webhooks/${id}/route.ts
import { createWebhookHandler } from 'verihook/next';

export const POST = createWebhookHandler('${id}', ${secret}, async (payload, result) => {
  // Runs only for a valid signature
  console.log(result.eventType, result.event);
});`,
    ],
    [
      "Express",
      `import express from 'express';
import { verihookExpress, type VerihookRequestAdditions } from 'verihook/express';

const app = express();

// Register before express.json(), or keep express.json() off this route
app.post('/webhooks/${id}', verihookExpress('${id}', ${secret}), (req, res) => {
  const { eventType, event } = (req as typeof req & VerihookRequestAdditions).verihook!;
  res.json({ received: true });
});`,
    ],
    [
      "Fastify",
      `import Fastify from 'fastify';
import { verihookFastify, verihookRawBody, type VerihookFastifyRequest } from 'verihook/fastify';

const app = Fastify();
await app.register(verihookRawBody);

app.post('/webhooks/${id}', { preHandler: verihookFastify('${id}', ${secret}) }, async (request) => {
  const { eventType, event } = (request as typeof request & VerihookFastifyRequest).verihook!;
  return { received: true };
});`,
    ],
    [
      "Hono",
      `import { Hono } from 'hono';
import { verihookHono, type VerihookVariables } from 'verihook/hono';

const app = new Hono<{ Bindings: { ${p.env}: string }; Variables: VerihookVariables }>();

app.post('/webhooks/${id}', verihookHono('${id}', (c) => c.env.${p.env}), (c) => {
  const { eventType, event } = c.get('verihook');
  return c.json({ received: true });
});`,
    ],
    [
      "NestJS",
      `// main.ts: NestFactory.create(AppModule, { rawBody: true })
import { Controller, Post, Req, UseGuards } from '@nestjs/common';
import { createVerihookGuard, type VerihookNestRequest } from 'verihook/nestjs';

@Controller('webhooks')
export class WebhooksController {
  @Post('${id}')
  @UseGuards(createVerihookGuard('${id}', ${secret}))
  handle(@Req() req: VerihookNestRequest) {
    const { eventType, event } = req.verihook!;
  }
}`,
    ],
    [
      "Nuxt / h3",
      `// server/api/webhooks/${id}.post.ts
import { createWebhookHandler } from 'verihook/h3';

export default defineEventHandler(
  createWebhookHandler('${id}', ${secret}, async (payload, result) => {
    console.log(result.eventType);
  }),
);`,
    ],
    [
      "SvelteKit",
      `// src/routes/webhooks/${id}/+server.ts
import { env } from '$env/dynamic/private';
import { createWebhookHandler } from 'verihook/sveltekit';

export const POST = createWebhookHandler('${id}', () => env.${p.env}, async (payload, result) => {
  console.log(result.eventType);
});`,
    ],
    [
      "Remix / React Router",
      `// app/routes/webhooks.${id}.ts
import { createWebhookHandler } from 'verihook/remix';

export const action = createWebhookHandler('${id}', ${secret}, async (payload, result) => {
  console.log(result.eventType);
});`,
    ],
    [
      "Astro",
      `// src/pages/api/webhooks/${id}.ts
import { createWebhookHandler } from 'verihook/astro';

export const prerender = false;
export const POST = createWebhookHandler('${id}', import.meta.env.${p.env}, async (payload, result) => {
  console.log(result.eventType);
});`,
    ],
    [
      "AWS Lambda",
      `import { createWebhookHandler } from 'verihook/lambda';

export const handler = createWebhookHandler('${id}', ${secret}, async (payload, result) => {
  console.log(result.eventType);
});`,
    ],
  ];
}

function testingSection(p) {
  if (p.signable === false) {
    return `## Testing

${p.name} signs with its own private key, so \`verihook/testing\` can't create ${p.name} webhooks. Use the provider's sandbox or simulator, or mock \`${p.fn}\` in unit tests.`;
  }
  const secretLine = p.testSecret
    ? `  secret: '${p.testSecret}',\n`
    : "";
  const secretNote = p.testSecret
    ? ""
    : `\n\n${p.name} uses a key pair. \`signWebhook\` generates one and returns the public key as \`hook.secret\`, so verify with that.`;
  return `## Testing

\`signWebhook\` from \`verihook/testing\` builds a correctly signed ${p.name} request for your tests:

${code(
  "ts",
  `import { signWebhook } from 'verihook/testing';
import { ${p.fn} } from 'verihook/${p.entry}';

const hook = await signWebhook('${p.id}', {
${secretLine}  payload: { id: 'evt_test' },
});

const result = await ${p.fn}(
  { headers: hook.headers, body: hook.body, url: hook.url },
  hook.secret,
);
// result.valid === true`,
)}${secretNote}

From the command line, \`npx verihook simulate ${p.id} --url http://localhost:3000/webhooks/${p.id}\` sends one to your local server.

See [Testing your handlers](../../guides/testing/) for supertest and Fetch \`Request\` examples.`;
}

function page(p) {
  const tabs = frameworkSnippets(p)
    .map(
      ([label, body]) =>
        `<TabItem label="${label}">\n\n${code("ts", body)}\n\n</TabItem>`,
    )
    .join("\n");
  const ids = [p.id, ...(p.aliases ?? [])].map((i) => `\`'${i}'\``).join(", ");
  const region = p.region ? ` (${p.region})` : "";
  const rows = [
    ["Identifier", ids],
    ["Import", `\`import { ${p.fn} } from 'verihook/${p.entry}'\``],
    ["Headers", p.headers.map((h) => `\`${h}\``.replace(/ \((.+)\)`$/, "` ($1)")).join("<br/>")],
    ["Signature", p.scheme],
    ["Replay window", p.tolerance ? `${p.tolerance} (\`options.tolerance\`)` : "None (the provider sends no timestamp)"],
    ["`result.eventType`", p.eventType],
  ];
  const table = [
    "| | |",
    "| :--- | :--- |",
    ...rows.map(([k, v]) => `| ${k} | ${v.replace(/\|/g, "\\|")} |`),
  ].join("\n");
  const notes = p.notes.length
    ? `## Things to know\n\n${p.notes.map((n) => `- ${n}`).join("\n")}\n`
    : "";
  const handshake = p.handshake ? `## Setup handshake\n\n${p.handshake}\n` : "";

  return `---
title: Verify ${p.name} webhooks
description: Verify ${p.name}${region} webhook signatures in Node.js, Next.js, Express, Fastify, Hono, NestJS, Nuxt, SvelteKit, Remix, Astro, AWS Lambda, Deno and Bun with verihook.
sidebar:
  label: ${p.name}
---

{/* Generated by scripts/generate-pages.mjs from src/data/providers.mjs. Edit the data file instead. */}

import { Tabs, TabItem } from '@astrojs/starlight/components';

Verify that a webhook really came from ${p.name}${region} before acting on it.

${table}

## Get your secret

${p.secret}

Store it in an environment variable (\`${p.env}\` below) and never commit it.

## Verify a request

${code(
  "ts",
  `import { ${p.fn} } from 'verihook/${p.entry}';

export async function POST(request: Request) {
  const result = await ${p.fn}(request, process.env.${p.env}!);

  if (!result.valid) {
    console.warn(result.code, result.reason, result.hint);
    return new Response('Invalid signature', { status: 401 });
  }

  console.log(result.eventType, result.event);
  return Response.json({ received: true });
}`,
)}

\`request\` can be a Fetch \`Request\` or \`{ headers, body, url? }\` with the **raw** body. \`verifyWebhook('${p.id}', request, secret)\` from \`verihook\` does the same. Read [why the raw body matters](../../guides/raw-body/) if verification fails behind a body parser.

## Framework examples

<Tabs syncKey="framework">
${tabs}
</Tabs>

Each adapter responds \`401\` to an invalid signature, \`413\` to a body over \`maxBodySize\` (2 MB by default) and \`200\` to a duplicate when you pass a \`dedupeStore\`.

${handshake}
${notes}
${testingSection(p)}

## Troubleshooting

Failed results carry a \`code\` and often a \`hint\` with the likely cause. See [Troubleshooting](../../troubleshooting/) for each error code.

[${p.name}'s webhook documentation](${p.docs})
`.replace(/\n{3,}/g, "\n\n");
}

function index() {
  const rows = providers
    .map(
      (p) =>
        `| [${p.name}](./${p.id}/) | \`'${p.id}'\`${(p.aliases ?? []).map((a) => `, \`'${a}'\``).join("")} | \`verihook/${p.entry}\` | ${p.region ?? ""} |`,
    )
    .join("\n");
  return `---
title: All providers
description: Every webhook provider verihook verifies, with its identifier and import path.
sidebar:
  order: 0
---

{/* Generated by scripts/generate-pages.mjs. */}

verihook verifies ${providers.length} providers out of the box. Anything else works with the [generic HMAC verifier or a custom provider](../guides/custom-providers/).

| Provider | Identifier | Import | Region |
| :--- | :--- | :--- | :--- |
${rows}
`;
}

rmSync(outDir, { recursive: true, force: true });
mkdirSync(outDir, { recursive: true });
writeFileSync(join(outDir, "index.mdx"), index());
for (const p of providers) {
  writeFileSync(join(outDir, `${p.id}.mdx`), page(p));
}
console.log(`Generated ${providers.length} provider pages in ${outDir}`);
