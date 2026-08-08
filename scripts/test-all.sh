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

node dist/cli.js simulate > /dev/null
echo -e "${GREEN}  ✓ CLI help menu rendered cleanly${NC}\n"

# 7. Module Exports Verification
echo -e "${YELLOW}7️⃣ Verifying CommonJS and ESM module exports...${NC}"
node -e "
const v = require('./dist/index.js');
const e = require('./dist/express.js');
const n = require('./dist/next.js');
const c = require('./dist/cli.js');
if (typeof v.verifyWebhook !== 'function' || typeof e.verihookExpress !== 'function' || typeof n.createWebhookHandler !== 'function') {
  console.error('Missing expected CommonJS exports');
  process.exit(1);
}
"
echo -e "${GREEN}  ✓ CommonJS require exports verified!${NC}"

node -e "
import('./dist/express.mjs').then(({ verihookExpress }) => {
  if (typeof verihookExpress !== 'function') {
    console.error('Missing ESM verihookExpress export');
    process.exit(1);
  }
});
"
echo -e "${GREEN}  ✓ ESM module import verified!${NC}\n"

echo -e "${GREEN}==================================================${NC}"
echo -e "${GREEN}🎉 ALL END-TO-END TESTS PASSED SUCCESSFULLY!${NC}"
echo -e "${GREEN}verihook is 100% verified and ready for release!${NC}"
echo -e "${GREEN}==================================================${NC}"
