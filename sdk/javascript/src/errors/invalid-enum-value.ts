/**
 * Thrown when a request carries an enum value that is neither a public short
 * name nor the wire spelling the server returns for that field.
 */
export class InvalidEnumValueError extends Error {
  /** The request field the value was given for. */
  public readonly field: string;
  /** The rejected value. */
  public readonly value: unknown;

  constructor(field: string, value: unknown) {
    super(`${field}: ${JSON.stringify(value)} is not a known value`);
    this.name = 'InvalidEnumValueError';
    this.field = field;
    this.value = value;
  }
}
