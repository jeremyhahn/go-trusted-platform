/**
 * Parses the EAB create form's "Expires in (seconds)" input.
 *
 * A blank input leaves expiresInSeconds out of the create request, which issues
 * a credential that never expires (docs/eab/api.md section 3; there is no
 * server default). Anything else must be a positive whole number of seconds no
 * larger than Number.MAX_SAFE_INTEGER; every other value is refused, so a typo
 * such as "-1" or "0" is caught here; leave the field blank for no expiry.
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
