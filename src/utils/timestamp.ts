/**
 * Converts a Unix epoch timestamp (in seconds or milliseconds) to seconds.
 * 13-digit millisecond timestamps (> 1e10) are divided by 1000 and floored.
 */
export function toEpochSeconds(ts: number): number {
  if (isNaN(ts) || !isFinite(ts)) {
    return ts;
  }
  if (Math.abs(ts) > 1e10) {
    return Math.floor(ts / 1000);
  }
  return Math.floor(ts);
}
