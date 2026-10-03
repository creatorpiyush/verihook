#!/usr/bin/env bash
set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}==================================================${NC}"
echo -e "${BLUE}🚀 Starting Full End-to-End Verihook Verification Suite${NC}"
echo -e "${BLUE}==================================================${NC}\n"

# 1. Code Style & Prettier Formatting
echo -e "${YELLOW}1️⃣ Checking code formatting...${NC}"
npm run format:check
echo -e "${GREEN}  ✓ Prettier formatting check passed!${NC}\n"

# 2. TypeScript Strict Typecheck
echo -e "${YELLOW}2️⃣ Running TypeScript strict typecheck...${NC}"
npm run typecheck
echo -e "${GREEN}  ✓ Typecheck passed with 0 errors!${NC}\n"

# 3. Vitest Coverage Suite
echo -e "${YELLOW}3️⃣ Running unit tests with V8 coverage...${NC}"
npm run test:coverage
echo -e "${GREEN}  ✓ Unit tests and 95%+ coverage verified!${NC}\n"

# 4. End-to-End Regression Suite
echo -e "${YELLOW}4️⃣ Running end-to-end regression suite...${NC}"
npm run test:regression
echo -e "${GREEN}  ✓ Regression suite passed!${NC}\n"

# 5. Production Package Build
echo -e "${YELLOW}5️⃣ Building ESM, CJS, and TypeScript declaration bundles...${NC}"
npm run build
echo -e "${GREEN}  ✓ Tsup build completed successfully!${NC}\n"

# 5b. Bundle size budget
echo -e "${YELLOW}📦 Checking bundle size budgets...${NC}"
npm run size
echo -e "${GREEN}  ✓ Bundles are within their size-limit budgets!${NC}\n"

# 6. User CLI Binary Simulations
echo -e "${YELLOW}6️⃣ Validating CLI binary execution & cURL generation...${NC}"

node dist/cli.js simulate stripe --curl > /dev/null
echo -e "${GREEN}  ✓ CLI simulate stripe --curl succeeded${NC}"

node dist/cli.js simulate github --event push --curl > /dev/null
echo -e "${GREEN}  ✓ CLI simulate github --event push --curl succeeded${NC}"

node dist/cli.js simulate twilio --curl > /dev/null
echo -e "${GREEN}  ✓ CLI simulate twilio --curl succeeded${NC}"

node dist/cli.js simulate svix --secret whsec_dGVzdF9zZWNyZXRfa2V5X2Zvcl9zdml4XzEyMw== --curl > /dev/null
echo -e "${GREEN}  ✓ CLI simulate svix --curl succeeded${NC}"

node dist/cli.js simulate lemonsqueezy --secret lemon_123 --curl > /dev/null
echo -e "${GREEN}  ✓ CLI simulate lemonsqueezy --curl succeeded${NC}"

node -e "require('./dist/cli.js').runListenServer({ command: 'listen', provider: 'stripe', secret: 'whsec_test', forwardTo: 'http://localhost:3000/webhooks/stripe' }).then(s => s.close())" > /dev/null
echo -e "${GREEN}  ✓ CLI listen live relay proxy binary startup succeeded${NC}"

node dist/cli.js > /dev/null
echo -e "${GREEN}  ✓ CLI help menu rendered cleanly${NC}\n"

# 7. Module Exports Verification
echo -e "${YELLOW}7️⃣ Verifying CommonJS and ESM module exports...${NC}"
node -e "
const v = require('./dist/index.js');
const e = require('./dist/express.js');
const n = require('./dist/next.js');
const c = require('./dist/cli.js');
if (
  typeof v.verifyWebhook !== 'function' ||
  typeof e.verihookExpress !== 'function' ||
  typeof n.createWebhookHandler !== 'function' ||
  typeof c.runListenServer !== 'function'
) {
  console.error('Missing expected CommonJS exports');
  process.exit(1);
}
"
echo -e "${GREEN}  ✓ CommonJS require exports verified!${NC}"

node -e "
Promise.all([
  import('./dist/express.mjs'),
  import('./dist/cli.mjs')
]).then(([{ verihookExpress }, { runListenServer }]) => {
  if (typeof verihookExpress !== 'function' || typeof runListenServer !== 'function') {
    console.error('Missing ESM exports');
    process.exit(1);
  }
});
"
echo -e "${GREEN}  ✓ ESM module import verified!${NC}"

node -e "
const adapters = {
  fastify: 'verihookFastify',
  hono: 'verihookHono',
  h3: 'createWebhookHandler',
  sveltekit: 'createWebhookHandler',
  remix: 'createWebhookHandler',
  astro: 'createWebhookHandler',
  lambda: 'createWebhookHandler',
  nestjs: 'createVerihookGuard',
};
Promise.all(
  Object.entries(adapters).map(async ([name, fn]) => {
    const cjs = require('./dist/' + name + '.js');
    const esm = await import('./dist/' + name + '.mjs');
    if (typeof cjs[fn] !== 'function' || typeof esm[fn] !== 'function') {
      throw new Error('Missing ' + fn + ' in verihook/' + name);
    }
  }),
).catch((err) => {
  console.error(err.message);
  process.exit(1);
});
"
echo -e "${GREEN}  ✓ Framework adapter subpath exports verified!${NC}\n"

node -e "
const pkg = require('./package.json');
const subpaths = Object.keys(pkg.exports).filter(
  (key) => key !== '.' && key !== './package.json' && !pkg.exports[key].import.includes('/cli'),
);
Promise.all(
  subpaths.map(async (key) => {
    const name = key.slice(2);
    const cjs = require('./dist/' + name + '.js');
    const esm = await import('./dist/' + name + '.mjs');
    if (Object.keys(cjs).length === 0 || Object.keys(esm).length === 0) {
      throw new Error('Empty exports in verihook/' + name);
    }
  }),
).then(() => {
  const { verifyStripe } = require('./dist/stripe.js');
  if (typeof verifyStripe !== 'function') throw new Error('verihook/stripe is missing verifyStripe');
}).catch((err) => {
  console.error(err.message);
  process.exit(1);
});
"
echo -e "${GREEN}  ✓ All per-provider and adapter subpaths load in CommonJS and ESM!${NC}\n"

echo -e "${GREEN}==================================================${NC}"
echo -e "${GREEN}🎉 ALL END-TO-END TESTS PASSED SUCCESSFULLY!${NC}"
echo -e "${GREEN}verihook is 100% verified and ready for release!${NC}"
echo -e "${GREEN}==================================================${NC}"
