## What does this change?

<!-- One or two sentences. Link the issue it closes: "Closes #123". -->

## Type

- [ ] New provider
- [ ] Bug fix
- [ ] Feature / adapter
- [ ] Docs or tests only

## New provider checklist

<!-- Delete this section if you're not adding a provider. See CONTRIBUTING.md, "Add a provider in 5 steps". -->

- Provider signature docs: <!-- link -->
- [ ] Verifier in `src/providers/`, registered in `src/providers/index.ts` and the `ProviderName` union
- [ ] `verify<Provider>` shortcut exported, event type added to `ProviderEventMap`
- [ ] Signing case in `src/testing/sign.ts` (or a clear error if it can't be signed locally), CLI sample payload, header in `diagnostics.ts`
- [ ] Tests: valid, wrong secret, modified body, missing headers, expired timestamp, known-good vector from the docs or SDK
- [ ] Docs entry in `docs/src/data/providers.mjs`, README table, ARCHITECTURE matrix, CHANGELOG `[Unreleased]`

## Checklist

- [ ] `npm run test:all` passes
- [ ] No new runtime dependencies
- [ ] No secrets or real customer payloads in tests or fixtures
