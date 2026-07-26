#!/bin/bash
set -e

echo "=== Running Pre-Commit Checks ==="

echo "1. Running typecheck..."
npm run typecheck

echo "2. Running unit tests..."
npm test

echo "=== All checks passed! Ready to commit ==="