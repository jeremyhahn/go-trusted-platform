import { InvalidEnumValueError } from '../errors/invalid-enum-value.js';

/**
 * Encodes an enum value for a request body.
 *
 * `names` maps each public short name to its wire spelling. The value may be
 * either: a short name is translated, and a wire spelling (what the server
 * returns in responses) passes through, so an object read from a response can
 * be sent back unchanged. A short name the map leaves undefined encodes as
 * undefined, which callers omit from the body. Anything else throws
 * InvalidEnumValueError rather than silently dropping the field.
 */
export function encodeEnum<K extends string, W extends string>(
  field: string,
  names: Readonly<Record<K, W>>,
  value: string,
): W;
export function encodeEnum<K extends string, W extends string>(
  field: string,
  names: Readonly<Record<K, W | undefined>>,
  value: string,
): W | undefined;
export function encodeEnum<K extends string, W extends string>(
  field: string,
  names: Readonly<Record<K, W | undefined>>,
  value: string,
): W | undefined {
  if (Object.prototype.hasOwnProperty.call(names, value)) {
    return names[value as K];
  }
  const wireNames: readonly (W | undefined)[] = Object.values(names);
  if (wireNames.includes(value as W)) {
    return value as W;
  }
  throw new InvalidEnumValueError(field, value);
}

/** encodeEnum for an optional field: undefined stays undefined. */
export function encodeOptionalEnum<K extends string, W extends string>(
  field: string,
  names: Readonly<Record<K, W | undefined>>,
  value: string | undefined,
): W | undefined {
  return value === undefined ? undefined : encodeEnum(field, names, value);
}
