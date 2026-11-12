/**
 * Parses the EAB create form's "Expires in (seconds)" input.
 *
 * An expiry is required: the input must be a positive whole number of seconds
 * no larger than Number.MAX_SAFE_INTEGER. Blank, zero and every other value
 * that is not a positive integer are refused, so no credential is ever issued
 * without an expiration.
 */
export type ParsedExpiresIn = { ok: true; seconds: number } | { ok: false };

export function parseExpiresIn(input: string): ParsedExpiresIn {
  const value = input.trim();
  if (value === "") return { ok: false };
  if (!/^[1-9][0-9]*$/.test(value)) return { ok: false };
  const seconds = Number(value);
  if (!Number.isSafeInteger(seconds)) return { ok: false };
  return { ok: true, seconds };
}
