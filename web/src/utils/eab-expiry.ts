/**
 * Parses the EAB create form's "Expires in (seconds)" input.
 *
 * A blank input leaves the expiry unset (the server's default). Anything else
 * must be a positive whole number of seconds no larger than
 * Number.MAX_SAFE_INTEGER; every other value is refused so that a typo such as
 * "-1" or "0" can never issue a non-expiring credential.
 */
export type ParsedExpiresIn = { ok: true; seconds?: number } | { ok: false };

export function parseExpiresIn(input: string): ParsedExpiresIn {
  const value = input.trim();
  if (value === "") return { ok: true };
  if (!/^[1-9][0-9]*$/.test(value)) return { ok: false };
  const seconds = Number(value);
  if (!Number.isSafeInteger(seconds)) return { ok: false };
  return { ok: true, seconds };
}
