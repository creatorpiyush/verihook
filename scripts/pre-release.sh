#!/bin/bash
set -e

echo "=== Running Pre-Release Checklist & Build ==="

echo "0. Running NPM install..."
npm install

echo "1. Checking code formatting..."
npm run format:check

echo "2. Running security audit..."
npm audit --audit-level=high

echo "3. Cleaning previous builds..."
npm run clean

echo "4. Running typecheck..."
npm run typecheck

echo "5. Running master test suite (coverage, regression, CLI, and exports)..."
npm run test:all

echo "6. Building dist packages..."
npm run build

echo "=== Build succeeded! ==="
echo "Checklist before publishing:"
echo " [ ] Incremented version in package.json?"
echo " [ ] Documented changes in CHANGELOG / Release Notes?"
echo " [ ] Verified documentation is up to date?"
echo " [ ] Code formatting check passed?"
echo " [ ] Coverage thresholds satisfied?"
echo " [ ] Security audit passed with zero vulnerabilities?"
echo "Ready to publish: npm publish"