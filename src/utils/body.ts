import { PayloadTooLargeError } from "../core/errors.js";

export { PayloadTooLargeError };

export const DEFAULT_MAX_BODY_SIZE = 2 * 1024 * 1024; // 2MB

/**
 * Reads a Web `Request` body as UTF-8, aborting once it exceeds `maxBytes`.
 */
export async function readWebBodyWithLimit(
  req: Request,
  maxBytes: number,
): Promise<string> {
  const declaredLength = Number(req.headers.get("content-length"));
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
    throw new PayloadTooLargeError();
  }
  if (!req.body) {
    return "";
  }

  const reader = req.body.getReader();
  const decoder = new TextDecoder();
  let totalBytes = 0;
  let text = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    totalBytes += value.byteLength;
    if (totalBytes > maxBytes) {
      // Not awaited: cancelling one branch of a cloned (tee'd) body only settles
      // once the other branch is consumed or cancelled, which may never happen.
      reader.cancel().catch(() => {});
      throw new PayloadTooLargeError();
    }
    text += decoder.decode(value, { stream: true });
  }
  return text + decoder.decode();
}
