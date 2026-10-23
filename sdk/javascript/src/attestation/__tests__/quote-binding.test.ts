/**
 * Unit tests for the quote channel-binding check (#482).
 *
 * A node quotes SHA-256(nonce || channelBinding). The check must accept that
 * quote, and refuse a quote of the bare nonce, a quote bound to another
 * binding, and anything that is not a TPM quote at all.
 */

import { describe, it, expect } from 'vitest';
import { QuoteBindingError, checkQuoteBinding, quotedData } from '../quote-binding.js';

const TPM_ST_ATTEST_QUOTE = 0x8018;
const TPM_ST_ATTEST_CERTIFY = 0x8017;

const nonce = new Uint8Array([1, 2, 3, 4]);
const callerBinding = new Uint8Array(32).fill(0xa1);
const relayBinding = new Uint8Array(32).fill(0xb2);

/** A TPMS_ATTEST: magic, type, qualifiedSigner, extraData, then clock info. */
function attest(extraData: Uint8Array, type = TPM_ST_ATTEST_QUOTE): Uint8Array {
  const signer = new Uint8Array([0x00, 0x0b, 0xee, 0xee]);
  const out = new Uint8Array(4 + 2 + 2 + signer.length + 2 + extraData.length + 17);
  const view = new DataView(out.buffer);
  view.setUint32(0, 0xff544347);
  view.setUint16(4, type);
  view.setUint16(6, signer.length);
  out.set(signer, 8);
  view.setUint16(8 + signer.length, extraData.length);
  out.set(extraData, 10 + signer.length);
  return out;
}

async function bound(binding: Uint8Array): Promise<Uint8Array> {
  const message = new Uint8Array([...nonce, ...binding]);
  return new Uint8Array(await crypto.subtle.digest('SHA-256', message));
}

function b64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

async function refusal(promise: Promise<void>): Promise<QuoteBindingError> {
  const err = await promise.then(
    () => undefined,
    (e: unknown) => e
  );
  expect(err).toBeInstanceOf(QuoteBindingError);
  return err as QuoteBindingError;
}

describe('quotedData', () => {
  it('returns the qualifying data of a quote', () => {
    expect(quotedData(attest(new Uint8Array([9, 8, 7])))).toEqual(new Uint8Array([9, 8, 7]));
  });

  it('refuses a certify structure', () => {
    expect(() => quotedData(attest(new Uint8Array([9]), TPM_ST_ATTEST_CERTIFY))).toThrow(
      /0x8017 is not a quote/
    );
  });

  it('refuses bytes without the TPM_GENERATED magic', () => {
    const notAttest = attest(new Uint8Array([9]));
    notAttest[0] = 0;
    expect(() => quotedData(notAttest)).toThrow(QuoteBindingError);
  });

  it('refuses a quote truncated inside its qualifying data', () => {
    const truncated = attest(new Uint8Array(32)).slice(0, 20);
    expect(() => quotedData(truncated)).toThrow(/truncated inside/);
  });

  it('refuses a quote truncated before its qualifying data', () => {
    expect(() => quotedData(attest(new Uint8Array(0)).slice(0, 9))).toThrow(/truncated before/);
  });
});

describe('checkQuoteBinding', () => {
  it('accepts a quote of SHA-256(nonce || channelBinding)', async () => {
    const quote = attest(await bound(callerBinding));
    await expect(checkQuoteBinding(b64(quote), b64(nonce), b64(callerBinding))).resolves.toBeUndefined();
  });

  it('refuses a quote of the bare nonce', async () => {
    const err = await refusal(checkQuoteBinding(b64(attest(nonce)), b64(nonce), b64(callerBinding)));
    expect(err.reason).toBe('not-bound');
  });

  it('refuses a quote bound to another connection under a rewritten echo', async () => {
    // A relay obtained the node's quote over its own connection, then told
    // the caller the binding was the caller's.
    const quote = attest(await bound(relayBinding));
    const err = await refusal(checkQuoteBinding(b64(quote), b64(nonce), b64(callerBinding)));
    expect(err.reason).toBe('not-bound');
  });

  it('refuses a quote returned without a channel binding', async () => {
    const quote = attest(await bound(callerBinding));
    for (const missing of [undefined, '']) {
      const err = await refusal(checkQuoteBinding(b64(quote), b64(nonce), missing));
      expect(err.reason).toBe('not-bound');
    }
  });

  it('refuses a channel binding that is not base64', async () => {
    const quote = attest(await bound(callerBinding));
    const err = await refusal(checkQuoteBinding(b64(quote), b64(nonce), '%%%'));
    expect(err.reason).toBe('malformed');
    expect(err.message).toMatch(/channelBinding/);
  });

  it('refuses a bound certify structure', async () => {
    const certify = attest(await bound(callerBinding), TPM_ST_ATTEST_CERTIFY);
    const err = await refusal(checkQuoteBinding(b64(certify), b64(nonce), b64(callerBinding)));
    expect(err.reason).toBe('malformed');
  });
});
