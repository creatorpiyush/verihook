# Contributing to verihook

Thanks for helping. The most useful contributions are new providers, framework examples, bug reports with a failing request, and documentation fixes. New providers are the easiest place to start.

> **Security issues:** don't open a public issue. Follow [SECURITY.md](./SECURITY.md).

## Setup

You need Node.js 18.17 or newer (CI uses Node 24).

```bash
git clone https://github.com/creatorpiyush/verihook.git
cd verihook
npm install
npm test
```

| Command | What it does |
| :--- | :--- |
| `npm test` | Unit tests (Vitest) |
| `npm run test:watch` | Tests in watch mode |
| `npm run typecheck` | Strict `tsc` on `src/` plus the type tests in `tests/types/` |
| `npm run format` | Prettier on `src/` and `tests/` |
| `npm run test:all` | Everything CI runs: format, typecheck, coverage, regression, build, CLI and export checks |

Run `npm run test:all` before you open a pull request.

## Ground rules

- **No runtime dependencies.** Use Web Crypto through the helpers in `src/core/crypto.ts` (`computeHmacSha256`, `verifyEd25519`, …) so the code also runs on edge runtimes such as Cloudflare Workers and Vercel Edge.
- **Verify the raw body.** Sign `req.rawBody`, the exact bytes received. Never sign a re-serialized object.
- **Compare signatures with `timingSafeEqual`**, never with `===`.
- **Return a result; don't throw** for a bad signature, header or timestamp. Use a `WebhookErrorCode` and a short `reason`.
- **Follow the provider's official docs.** Link them in the provider file and the PR.

## Add a provider in 5 steps

[`src/providers/_template.ts`](./src/providers/_template.ts) is a working verifier for a fictional "Acme" service. [`tests/provider-template.test.ts`](./tests/provider-template.test.ts) tests it. Copy both and rename. The examples below use a provider called `acme`.

### 1. Write the verifier

```bash
cp src/providers/_template.ts src/providers/acme.ts
cp tests/provider-template.test.ts tests/acme.test.ts
```

In the copy, change the headers, the signed string and the encoding to match the provider's docs. Then make these changes:

- **Timestamp header:** check it against `options.tolerance` (default 300 s) and `options.now`, and return the parsed `timestamp`.
- **`eventType`:** implement it if the event name isn't in the body's `type`, `event` or `event_type` field. It may also come from a header, such as GitHub's `x-github-event`.
- **Payload shape:** add an `AcmeEvent` interface to `src/core/event-types.ts` describing the stable envelope fields. Leave provider objects loosely typed and keep the `[key: string]: unknown` index signature. Then add `acme: AcmeEvent` to `ProviderEventMap` and export the type from `src/index.ts`.

### 2. Register it

- **`src/providers/index.ts`:** import the verifier, add it to `providers` (plus any alias names that share it) and to the named exports.
- **`src/core/types.ts`:** add `"acme"` to the `ProviderName` union.
- **`src/core/verifier.ts`:** add `export const verifyAcme = shortcut("acme");`.
- **`src/index.ts`:** export `verifyAcme`.

### 3. Make it signable

These changes let users test against your provider with `verihook/testing` and the CLI.

- **`src/testing/sign.ts`:** add a `case "acme":` that produces the same headers the provider sends, then add `"acme"` to `SIGNABLE_PROVIDERS`. If the provider signs with a private key you can't generate locally, add a case that throws a clear error instead (as the `paypal` case does) and leave the provider out of `SIGNABLE_PROVIDERS`.
- **`src/cli/index.ts`:** add a sample payload to `simulationSample()` and the name to the "Supported Providers" help text.
- **`src/core/diagnostics.ts`:** add the provider's signature header to `SIGNATURE_HEADERS`. Then, when someone verifies an Acme request with the wrong provider, the hint names Acme.

### 4. Test it

- Cover a valid signature, a wrong secret, a modified body, missing headers, and an expired timestamp (where the provider has one).
- **Add a known-good test vector** if the provider publishes one: a payload, secret and signature from its docs or official SDK. A test that only checks your own signer can pass while both sides are wrong.
- `tests/testing-helpers.test.ts` round-trips every entry in `SIGNABLE_PROVIDERS` automatically.

### 5. Document it

- **`README.md`:** add a row to "Supported Providers" with the identifier and headers.
- **`ARCHITECTURE.md`:** add a row to the "Provider Implementation Matrix".
- **`CHANGELOG.md`:** add a line under `## [Unreleased]`. Create that section at the top if it isn't there.

## Pull requests

- **Branch:** name it `type/short-description`, for example `feat/paystack-provider` or `fix/slack-form-bodies`.
- **Commits:** use [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`.
- **Scope:** keep each PR focused on one provider, fix or feature.
- **Description:** fill in the PR template and link the provider docs you followed.
- **Releases:** the maintainer handles version bumps, release notes and npm releases. Don't change `version` in `package.json`.

## Reporting bugs

Use the [bug report form](https://github.com/creatorpiyush/verihook/issues/new/choose). The fastest reports to fix include:

- the provider, your framework and runtime versions;
- the `code`, `reason` and `hint` from the failed result;
- how your route reads the body (for example `express.json()`, `express.raw()`, `await request.text()`).

**Never post real secrets or production webhook payloads.** You can reproduce with `signWebhook()` from `verihook/testing` instead.

## License

By contributing, you agree that your contributions are licensed under the [MIT License](./LICENSE).
