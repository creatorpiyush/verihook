# Security Policy

`verihook` is a security-adjacent library providing universal, zero-dependency signature verification and SSRF-hardened proxying for incoming webhooks. We take security seriously and appreciate responsible disclosure of potential security vulnerabilities.

---

## Supported Versions

We actively maintain and provide security patches for the following versions of `verihook`:

| Version | Supported | Security Notes |
| :--- | :--- | :--- |
| `1.9.x` | :white_check_mark: | Current release family. Actively maintained. |
| `1.8.x` | :x: | Superseded by `1.9.x` (drop-in upgrade, no breaking changes). |
| `1.7.x` | :x: | Affected by PayPal signature forgery via HMAC fallback. Upgrade to latest `1.9.x`. |
| `< 1.7.0` | :x: | Legacy release (also affected by the PayPal issue). Upgrade to latest `1.9.x`. |

---

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues.**

If you discover a potential vulnerability, security bug, or flaw in `verihook`:

1. **GitHub Security Advisory (Preferred)**: Submit a private report via [GitHub Security Advisories](https://github.com/creatorpiyush/verihook/security/advisories/new).
2. **Direct Email**: Send a detailed disclosure to `ipiyushanand24@gmail.com` with:
   - Type of vulnerability (e.g. timing attack, SSRF bypass, payload injection, replay vulnerability).
   - Affected provider(s), function(s), or CLI subcommands.
   - Step-by-step proof-of-concept (PoC) or reproduction script.
   - Any potential impact assessment or suggested remediation.

### Response Timelines

- **Acknowledgement**: Within 24 hours of receipt.
- **Initial Triage & Assessment**: Within 48 hours.
- **Fix & Patch Release**: Critical security issues will receive a patch release (e.g. semver patch) within 72 hours of confirmation.
- **Public Disclosure**: Coordinated release published alongside the security fix and CVE allocation if applicable.

---

## Core Security Guarantees & Architecture

`verihook` enforces several design principles to protect application servers:

- 🔐 **Constant-Time Comparison**: All HMAC signature header checks utilize timing-safe byte array comparisons (`crypto.timingSafeEqual` / `timingSafeEqual`) to prevent side-channel timing attacks.
- 📦 **Zero External Runtime Dependencies**: Eliminates supply chain risks, transitive dependency vulnerabilities, and unverified package dependencies.
- 🌐 **SSRF Origin Hardening**: Local relay proxy listeners (`npx verihook listen`) validate target origins and block loopback, octal/hex IP tricks, link-local, and cloud metadata endpoints (`169.254.169.254`). *Note: Denylist host/IP enumeration provides best-effort defense-in-depth hardening and is not a substitute for network-level egress isolation.*
- ⚡ **Bounded Stream Allocation**: Input request body processing enforces configurable byte limits (`maxBodySize`, default 2MB) to protect against memory exhaustion Denial of Service (DoS) attacks.
- ⏳ **Replay Attack Protection**: Built-in header timestamp tolerance verification (`tolerance` option) and stateful deduplication stores (`MemoryDedupeStore`).

---

## Best Practices for Integrating `verihook`

To ensure your application remains secure when processing webhooks:

1. **Preserve Raw Body Bytes**: Pass raw, unparsed request bodies (`string` or `Uint8Array`) to `verifyWebhook`. Do not pre-parse JSON payloads before signature checking.
2. **Use Secret Managers**: Store webhook secrets in environment variables or secret vaults. Never hardcode secrets in source code.
3. **Enable Timestamp Tolerance**: Keep `tolerance` enabled (default: 300 seconds) for providers with timestamped headers to reject replayed requests.
4. **Use Event Deduplication**: For idempotent handling, pass a `dedupeStore` option (`MemoryDedupeStore` or Redis adapter) to prevent duplicate webhook processing.
5. **Network Isolation for Outbound Requests**: Rely on network-level egress controls (VPC security groups, firewall rules, or egress proxies) rather than application-level IP denylists for primary SSRF prevention.
