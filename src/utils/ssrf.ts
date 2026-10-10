const BLOCKED_HOSTNAMES = new Set([
  "169.254.169.254",
  "169.254.170.2",
  "168.63.129.16",
  "100.100.100.200",
  "metadata.google.internal",
  "metadata.tencentyun.com",
  "169.254.169.254.ipv4.super-int.sub",
  "instance-data",
]);

/**
 * Loopback, private (RFC 1918), CGNAT, unspecified and IPv6 unique-local /
 * link-local hosts, plus `localhost` names. Expects a hostname as `new URL()`
 * normalizes it (hex, decimal and octal IPv4 forms become dotted decimal).
 */
export function isPrivateNetworkHost(hostname: string): boolean {
  const cleanHost = hostname
    .toLowerCase()
    .replace(/^\[|\]$/g, "")
    .replace(/\.$/, "");

  if (cleanHost.endsWith(".localhost")) return true;

  // IPv6 unique-local (fc00::/7) and link-local (fe80::/10).
  if (/^f[cd][0-9a-f]{0,2}:/.test(cleanHost)) return true;
  if (/^fe[89ab][0-9a-f]?:/.test(cleanHost)) return true;
  if (cleanHost === "::") return true;

  // IPv4-mapped IPv6, as `new URL()` writes it: ::ffff:7f00:1 = 127.0.0.1.
  const mapped = cleanHost.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (mapped) {
    const hi = parseInt(mapped[1], 16);
    const lo = parseInt(mapped[2], 16);
    return isPrivateNetworkHost(
      `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`,
    );
  }

  if (
    cleanHost === "localhost" ||
    cleanHost === "127.0.0.1" ||
    cleanHost === "0.0.0.0" ||
    cleanHost === "0" ||
    cleanHost === "::1" ||
    cleanHost === "0177.0.0.1" ||
    cleanHost === "0x7f000001" ||
    cleanHost === "2130706433"
  ) {
    return true;
  }

  const ipMatch = cleanHost.match(
    /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/,
  );

  if (!ipMatch) {
    return false;
  }

  const [_, o1, o2] = ipMatch.map(Number);

  // 0.0.0.0/8
  if (o1 === 0) return true;
  // 10.0.0.0/8
  if (o1 === 10) return true;
  // 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
  if (o1 === 172 && o2 >= 16 && o2 <= 31) return true;
  // 192.168.0.0/16
  if (o1 === 192 && o2 === 168) return true;
  // 127.0.0.0/8 (Loopback)
  if (o1 === 127) return true;
  // 100.64.0.0/10 (Carrier-Grade NAT)
  if (o1 === 100 && o2 >= 64 && o2 <= 127) return true;
  // 169.254.0.0/16 (link-local, cloud metadata)
  if (o1 === 169 && o2 === 254) return true;
  // 224.0.0.0/3 (multicast, reserved, broadcast)
  if (o1 >= 224) return true;

  return false;
}

/**
 * Denylist-based SSRF host origin validation.
 *
 * Provides best-effort defense-in-depth hardening against known cloud metadata
 * endpoints (e.g., 169.254.169.254) and common encoding bypasses.
 * Note: Denylist-based validation is inherently incomplete and is not a substitute
 * for network-level isolation (such as VPC security groups, firewalls, or egress proxies).
 */
export function isBlockedSsrfHost(hostname: string): boolean {
  const cleanHost = hostname.toLowerCase().replace(/^\[|\]$/g, "");

  if (BLOCKED_HOSTNAMES.has(cleanHost)) {
    return true;
  }

  // Check 169.254.0.0/16 Link-Local subnet range (AWS/GCP/Azure/OpenStack metadata block)
  const ipMatch = cleanHost.match(
    /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/,
  );
  if (ipMatch) {
    const oct1 = Number(ipMatch[1]);
    const oct2 = Number(ipMatch[2]);
    if (oct1 === 169 && oct2 === 254) {
      return true;
    }
  }

  // Check octal IP notation (e.g. 0251.0376.0251.0376 = 169.254.169.254)
  const octalMatch = cleanHost.match(/^0[0-7]+\.0[0-7]+\.0[0-7]+\.0[0-7]+$/);
  if (octalMatch) {
    const parts = cleanHost.split(".").map((p) => parseInt(p, 8));
    if (parts[0] === 169 && parts[1] === 254) {
      return true;
    }
  }

  // Check IPv4-mapped IPv6 (::ffff:169.254.x.x) or fe80:: link-local IPv6
  if (
    cleanHost.startsWith("::ffff:169.254.") ||
    cleanHost.startsWith("fe80:") ||
    cleanHost.startsWith("::ffff:a9fe:")
  ) {
    return true;
  }

  // Check decimal representation of 169.254.169.254 (2852039166) or hex representations (0xa9fea9fe)
  if (
    cleanHost === "2852039166" ||
    cleanHost === "0xa9fea9fe" ||
    cleanHost === "0xa9.0xfe.0xa9.0xfe"
  ) {
    return true;
  }

  return false;
}

/**
 * Whether a hostname (as normalized by `new URL()`) is anything but a public
 * internet address. A public *name* that resolves to a private IP is not
 * caught: that needs DNS pinning or an egress proxy.
 */
export function isNonPublicHost(hostname: string): boolean {
  return isPrivateNetworkHost(hostname) || isBlockedSsrfHost(hostname);
}
