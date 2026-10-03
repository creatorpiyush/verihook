#!/usr/bin/env node
// Turns coverage/coverage-summary.json (vitest json-summary reporter) into a
// shields.io endpoint file: https://shields.io/badges/endpoint-badge
import { readFileSync, writeFileSync } from "node:fs";

const [
  input = "coverage/coverage-summary.json",
  output = "coverage/badge.json",
] = process.argv.slice(2);

const { total } = JSON.parse(readFileSync(input, "utf8"));
const pct = total.lines.pct;
const color =
  pct >= 95
    ? "brightgreen"
    : pct >= 90
      ? "green"
      : pct >= 80
        ? "yellow"
        : "red";

writeFileSync(
  output,
  JSON.stringify({
    schemaVersion: 1,
    label: "coverage",
    message: `${pct.toFixed(1)}%`,
    color,
  }) + "\n",
);
console.log(`coverage ${pct}% -> ${output}`);
