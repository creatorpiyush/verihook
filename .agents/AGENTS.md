# Agent Guidelines & Engineering Standards

## Node.js Code Quality & Security Practices

- **Dependency Hygiene**:
  - Pin exact package versions in `package.json` without semver range carets (`^`) or tildes (`~`) and commit the lockfile (`package-lock.json`).
  - Run `npm audit` (or Snyk/OSV-Scanner) before adding new dependencies. Audit transitive dependency manifests (`package-lock.json` / `node_modules`) for unverified `postinstall` scripts; prefer well-maintained packages with active maintainers and community adoption.

- **Safe API Usage**:
  - Do NOT use `eval()`, `new Function()`, or `child_process.exec()` with unsanitized inputs.
  - Avoid `vm` / `vm2` sandboxes for untrusted code execution (use `isolated-vm` or OS-level sandboxes if untrusted JS execution is required).

- **Input Validation**:
  - Enforce schema validation (e.g., Zod schemas) on all untrusted input entry points (request bodies, query params, headers, file uploads) instead of hand-rolled checks.

- **Injection & SSRF Prevention**:
  - Use parameterized queries for database interactions.
  - Escape dynamic quotes (`replace(/"/g, '\\"')`) when constructing JQL/CQL query strings.
  - Enforce SSRF origin validation on HTTP client requests to block requests to external origins, loopback IPs, or cloud metadata endpoints (`169.254.169.254`).
  - Avoid string-concatenated shell commands; escape output rendered into HTML or templates.

- **Secrets Management**:
  - Never hardcode credentials, tokens, or API keys in source code.
  - Ensure `.env` files are present in `.gitignore`.
  - Fetch secrets from environment variables or secret managers at runtime, and never output secrets in logs.

- **Static Analysis & CI Integration**:
  - Integrate `eslint-plugin-security`, Semgrep Node.js rulesets, or `npm audit --production` as required CI checks.

- **Least-Privilege & Hardened Runtime**:
  - Run Node processes under non-root user accounts.
  - Set `NODE_ENV=production` appropriately in non-development environments.
  - Enforce standard HTTP security headers (`X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `HSTS`, `CSP`), remove `X-Powered-By`, and set explicit request body size limits (e.g. `express.json({ limit: '2mb' })`) across all server ports.

## Error Handling & Resilience

- Never suppress errors silently; log structured error contexts with stack traces when appropriate.
- Classify errors clearly between client errors (4xx / invalid input) and internal server errors (5xx / upstream failure).
- Implement graceful shutdown listeners (`SIGTERM`, `SIGINT`) to drain HTTP connections and SSE sessions cleanly.
- Handle all async promise rejections (`process.on('unhandledRejection')`); never leave unhandled rejections unhandled.

## Logging & Observability

- Use structured logging (`logger.info`, `logger.error`, `logger.warn`) rather than raw `console.log`.
- Redact or sanitize sensitive headers (`Authorization`, `mcp-session-id`, auth tokens, passwords) before outputting logs.
- Attach context metadata (e.g. `toolName`, `sessionID`, `jql`, `spaceKey`) to log messages for end-to-end request tracing.

## TypeScript & Type Safety

- Enforce strict TypeScript compilation (`strict: true` in `tsconfig.json`).
- Avoid `any`; use `unknown` or explicit interface/type definitions.
- Enforce Zod schemas for runtime API request/response boundaries and MCP tool parameter validation.

## Payload Optimization & Disk Offloading

- Strip redundant API metadata (`_links`, `_expandable`, avatars, user metadata noise) before returning tool responses.
- Offload large text responses (>4KB) to local scratch/artifact storage to prevent LLM context window bloat.

## Testing & Verification Standards

- Require unit tests for new MCP tools, HTTP routes, client methods, and prompt definitions using `vitest`.
- Mock external HTTP requests (`jiraClient`, `confluenceClient`) in unit tests for fast, isolated, and deterministic test runs.
- Run `npm test && npm run build` before finalizing any code changes to guarantee 100% test pass rate and clean compilation.
