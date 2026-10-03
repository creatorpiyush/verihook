interface DenoPermissions {
  permissions?: {
    querySync?(descriptor: { name: "env"; variable: string }): {
      state: string;
    };
  };
}

/**
 * Reads NODE_ENV without failing where environment access is restricted. Deno
 * throws (or prompts) when the script runs without --allow-env, so it is only
 * read there when access is already granted.
 */
export function readNodeEnv(): string | undefined {
  try {
    const deno = (globalThis as { Deno?: DenoPermissions }).Deno;
    if (
      deno?.permissions?.querySync &&
      deno.permissions.querySync({ name: "env", variable: "NODE_ENV" })
        .state !== "granted"
    ) {
      return undefined;
    }
    return typeof process !== "undefined" ? process.env?.NODE_ENV : undefined;
  } catch {
    return undefined;
  }
}
