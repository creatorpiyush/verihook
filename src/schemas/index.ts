export interface ParsedCliArgs {
  provider?: string;
  url?: string;
  secret?: string;
  event?: string;
  printCurl?: boolean;
  allowRemote?: boolean;
}

export interface ParsedVerifyWebhookOptions {
  tolerance?: number;
  url?: string;
  webhookId?: string;
  now?: number;
  headerName?: string;
  algorithm?: "sha256" | "sha1" | "sha512";
  encoding?: "hex" | "base64" | "prefix-hex";
  onVerify?: (...args: unknown[]) => unknown;
  log?: (...args: unknown[]) => unknown;
  maxBodySize?: number;
}

export interface SchemaValidationResult<T> {
  success: boolean;
  data: T;
  errors: string[];
}

export function validateCliArgs(
  input: Record<string, unknown>,
): SchemaValidationResult<ParsedCliArgs> {
  const errors: string[] = [];
  const result: ParsedCliArgs = {};

  if (input.provider !== undefined) {
    if (typeof input.provider !== "string" || input.provider.trim() === "") {
      errors.push("provider must be a non-empty string");
    } else {
      result.provider = input.provider.trim();
    }
  }

  if (input.url !== undefined && input.url !== "") {
    if (typeof input.url !== "string") {
      errors.push("url must be a string");
    } else {
      try {
        new URL(input.url);
        result.url = input.url;
      } catch {
        errors.push(`Invalid URL format: "${input.url}"`);
      }
    }
  }

  if (input.secret !== undefined) {
    if (typeof input.secret !== "string") {
      errors.push("secret must be a string");
    } else {
      result.secret = input.secret;
    }
  }

  if (input.event !== undefined) {
    if (typeof input.event !== "string") {
      errors.push("event must be a string");
    } else {
      result.event = input.event;
    }
  }

  if (input.printCurl !== undefined) {
    result.printCurl = Boolean(input.printCurl);
  }

  if (input.allowRemote !== undefined) {
    result.allowRemote = Boolean(input.allowRemote);
  }

  return {
    success: errors.length === 0,
    data: result,
    errors,
  };
}

export function validateVerifyWebhookOptions(
  input: Record<string, unknown>,
): SchemaValidationResult<ParsedVerifyWebhookOptions> {
  const errors: string[] = [];
  const result: ParsedVerifyWebhookOptions = {};

  if (input.tolerance !== undefined) {
    if (
      typeof input.tolerance !== "number" ||
      isNaN(input.tolerance) ||
      input.tolerance < 0
    ) {
      errors.push("tolerance must be a non-negative number");
    } else {
      result.tolerance = input.tolerance;
    }
  }

  if (input.algorithm !== undefined) {
    if (
      input.algorithm !== "sha256" &&
      input.algorithm !== "sha1" &&
      input.algorithm !== "sha512"
    ) {
      errors.push('algorithm must be one of "sha256", "sha1", or "sha512"');
    } else {
      result.algorithm = input.algorithm;
    }
  }

  if (input.encoding !== undefined) {
    if (
      input.encoding !== "hex" &&
      input.encoding !== "base64" &&
      input.encoding !== "prefix-hex"
    ) {
      errors.push('encoding must be one of "hex", "base64", or "prefix-hex"');
    } else {
      result.encoding = input.encoding;
    }
  }

  if (input.maxBodySize !== undefined) {
    if (
      typeof input.maxBodySize !== "number" ||
      isNaN(input.maxBodySize) ||
      input.maxBodySize <= 0
    ) {
      errors.push("maxBodySize must be a positive number");
    } else {
      result.maxBodySize = input.maxBodySize;
    }
  }

  return {
    success: errors.length === 0,
    data: result,
    errors,
  };
}
