/**
 * Quote channel binding (#482).
 *
 * A node never quotes the caller's nonce as sent. It quotes
 * SHA-256(nonce || channelBinding), where channelBinding is the TLS exporter
 * (label EXPORTER-attested-peer) of the connection the request arrived on,
 * and returns channelBinding beside the quote. That is what stops a relay
 * from asking the node for a quote of someone else's nonce and handing it on.
 *
 * The Go SDK derives the exporter from its own connection and refuses a
 * quote bound to any other (sdk/go/quotebind). A browser cannot read the TLS
 * exporter, so this check is weaker: it proves the quote is bound to the
 * channelBinding the node returned — never a quote of the bare nonce — but
 * not that channelBinding is this page's own connection. Sending the
 * returned channelBinding to verify is what makes a bound quote verify.
 */

/** TPM_GENERATED_VALUE, the magic every TPM-produced TPMS_ATTEST starts with. */
const TPM_GENERATED_VALUE = 0xff544347;

/** TPM_ST_ATTEST_QUOTE, the TPMS_ATTEST type of a quote. */
const TPM_ST_ATTEST_QUOTE = 0x8018;

/** Why a quote failed the binding check. */
export type QuoteBindingReason = 'malformed' | 'not-bound';

/**
 * Error thrown when a quote is not a TPM quote or is not bound to the
 * nonce and channel binding it was returned with.
 */
export class QuoteBindingError extends Error {
  /** Why the quote was refused. */
  public readonly reason: QuoteBindingReason;

  constructor(reason: QuoteBindingReason, message: string) {
    super(message);
    this.name = 'QuoteBindingError';
    this.reason = reason;
  }
}

/**
 * Returns the qualifying data (TPMS_ATTEST.extraData) of a TPM quote.
 *
 * Refuses anything that is not a TPMS_ATTEST of type TPM_ST_ATTEST_QUOTE, so
 * a certify or NV-certify structure can never pass as a quote.
 */
export function quotedData(quote: Uint8Array): Uint8Array {
  const view = new DataView(quote.buffer, quote.byteOffset, quote.byteLength);
  // magic(4) type(2) qualifiedSigner.size(2)
  if (quote.byteLength < 8 || view.getUint32(0) !== TPM_GENERATED_VALUE) {
    throw new QuoteBindingError('malformed', 'quote is not a TPMS_ATTEST structure');
  }
  const type = view.getUint16(4);
  if (type !== TPM_ST_ATTEST_QUOTE) {
    throw new QuoteBindingError('malformed', `attestation type 0x${type.toString(16)} is not a quote`);
  }
  const extraDataAt = 8 + view.getUint16(6);
  if (extraDataAt + 2 > quote.byteLength) {
    throw new QuoteBindingError('malformed', 'quote is truncated before its qualifying data');
  }
  const extraDataEnd = extraDataAt + 2 + view.getUint16(extraDataAt);
  if (extraDataEnd > quote.byteLength) {
    throw new QuoteBindingError('malformed', 'quote is truncated inside its qualifying data');
  }
  return quote.slice(extraDataAt + 2, extraDataEnd);
}

/**
 * Checks that a quote is bound: its qualifying data must equal
 * SHA-256(nonce || channelBinding). All arguments are base64, as the API
 * carries them.
 *
 * @throws QuoteBindingError when channelBinding is missing, the quote is not
 * a TPM quote, or the quote is bound to anything else — including the bare
 * nonce a relay oracle would have quoted.
 */
export async function checkQuoteBinding(
  quote: string,
  nonce: string,
  channelBinding: string | undefined
): Promise<void> {
  if (channelBinding === undefined || channelBinding === '') {
    throw new QuoteBindingError('not-bound', 'the node returned no channel binding with the quote');
  }
  const binding = decodeBase64('channelBinding', channelBinding);
  const nonceBytes = decodeBase64('nonce', nonce);
  const got = quotedData(decodeBase64('quote', quote));

  const message = new Uint8Array(nonceBytes.length + binding.length);
  message.set(nonceBytes);
  message.set(binding, nonceBytes.length);
  const want = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', message));

  if (!equalBytes(got, want)) {
    throw new QuoteBindingError(
      'not-bound',
      'the quote is not bound to the nonce and channel binding it was returned with'
    );
  }
}

function decodeBase64(field: string, value: string): Uint8Array {
  let binary: string;
  try {
    binary = atob(value);
  } catch {
    throw new QuoteBindingError('malformed', `${field} is not base64`);
  }
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}
