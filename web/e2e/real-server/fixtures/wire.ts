/**
 * Reading the platform REST API's wire format in the real-server specs
 * (#2034, epic #1665).
 *
 * Every REST answer is a {code, success, error, payload} envelope, and
 * protojson writes int64 and uint64 fields as decimal strings. A spec that
 * compares the page with what the server answered reads the payload through
 * unwrapPayload and every count through wireCount.
 */

/** Returns the payload of a success envelope; throws on an error envelope. */
export function unwrapPayload<T>(body: unknown): T {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    throw new Error(`not a response envelope: ${JSON.stringify(body)}`);
  }
  const env = body as { code?: unknown; success?: unknown; error?: unknown; payload?: unknown };
  if (env.success !== true || env.payload === undefined || env.payload === null) {
    const reason = typeof env.error === 'string' ? env.error : JSON.stringify(env.error ?? null);
    throw new Error(
      `error envelope (code ${String(env.code)}, success ${String(env.success)}): ${reason}` +
        (env.success === true ? ' (no payload)' : ''),
    );
  }
  return env.payload as T;
}

/**
 * Reads a protojson count: a non-negative safe integer number, or the
 * decimal string protojson writes for int64/uint64. Throws on anything else,
 * including a string beyond Number.MAX_SAFE_INTEGER.
 */
export function wireCount(v: unknown): number {
  if (typeof v === 'number') {
    if (Number.isSafeInteger(v) && v >= 0) return v;
    throw new Error(`count ${v} is not a non-negative safe integer`);
  }
  if (typeof v === 'string' && /^[0-9]+$/.test(v)) {
    const n = Number(v);
    if (Number.isSafeInteger(n)) return n;
    throw new Error(`count "${v}" is beyond Number.MAX_SAFE_INTEGER`);
  }
  throw new Error(`count ${JSON.stringify(v)} is neither a number nor a decimal string`);
}
