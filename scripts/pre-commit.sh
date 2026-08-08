#!/bin/bash
set -e

echo "=== Running Pre-Commit Checks ==="

echo "0. Running NPM install..."
npm install

echo "1. Checking code formatting..."
npm run format:check

echo "2. Running security audit..."
npm audit --audit-level=high

echo "3. Running typecheck..."
npm run typecheck

echo "4. Running unit tests with coverage..."
npm run test:coverage

echo "5. Verifying package build..."
npm run build

echo "=== All checks passed! Ready to commit ==="