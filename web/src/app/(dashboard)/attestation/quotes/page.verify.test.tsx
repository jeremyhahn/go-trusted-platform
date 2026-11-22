import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import type { HostManifest } from 'trusted-platform-sdk';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import QuotesPage from './page';
import { parseAkHandle, parsePcrIndices } from './quote-verify-card';

// #2038: the quotes page asks a node for a TPM quote (GetAttestationQuote) and
// verifies it (VerifyAttestationQuote) through useAttestationVerify and the
// SDK client, with the nonce and the channel binding the quote came back with.

const MANIFESTS = 'GET /api/v1/attestation/manifests';
const QUOTE = 'POST /api/v1/attestation/quote';
const QUOTE_VERIFY = 'POST /api/v1/attestation/quote/verify';

const Q = { quoteData: 'cQ==', signature: 'c2ln', signatureAlgorithm: 'SHA256-RSAPSS', pcrValues: [], nonce: 'bg==' };
const STATUS = { success: true, message: '' };

const M1: HostManifest = {
  id: 'm1',
  hostId: 'host-a',
  timestamp: '2026-11-20T10:00:00Z',
  nonce: 'bg==',
  vms: [],
  containers: [],
  merkleRoot: 'cm9vdA==',
  signature: 'c2ln',
  signatureAlgorithm: 'ECDSA-SHA256',
  version: '1',
} as HostManifest;
const M2: HostManifest = { ...M1, id: 'm2', hostId: 'host-b' } as HostManifest;

const ATTESTATION_OPS = [MANIFESTS, QUOTE, QUOTE_VERIFY];

// The server's capabilities listing: every attestation op enabled except those in off.
function caps(off: string[] = []): Answer {
  const capabilities = ATTESTATION_OPS.map((op) =>
    off.includes(op)
      ? { op, kind: 'route', enabled: false, reason: 'not-configured: attestation' }
      : { op, kind: 'route', enabled: true },
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

function routes(extra: Record<string, Answer>): Record<string, Answer> {
  return {
    'GET /api/v1/capabilities': caps(),
    [MANIFESTS]: ok({ manifests: [M1, M2], total: 2 }),
    ...extra,
  };
}

async function askForQuote() {
  const card = await screen.findByTestId('quote-verify');
  fireEvent.change(within(card).getByLabelText('AK handle'), { target: { value: '0x81010001' } });
  fireEvent.change(within(card).getByLabelText('PCRs'), { target: { value: '0, 7' } });
  fireEvent.change(within(card).getByLabelText('Nonce'), { target: { value: 'bm9uY2U=' } });
  fireEvent.click(await within(card).findByRole('button', { name: 'Get quote' }));
  return card;
}

describe('QuotesPage quote verify', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('asks for a quote with the config and nonce', async () => {
    const sent = stubControlPlane(routes({ [QUOTE]: ok({ status: STATUS, quote: Q, channelBinding: 'Y2I=' }) }));
    render(withControlPlane(<QuotesPage />));
    await askForQuote();

    const result = await screen.findByTestId('quote-result');
    const posts = sent.filter((r) => r.method === 'POST' && r.path === '/api/v1/attestation/quote');
    expect(posts).toHaveLength(1);
    expect(posts[0].body).toEqual({
      config: { akHandle: 2164326401, pcrIndices: [0, 7], hashAlgorithm: 'ATTESTATION_HASH_ALGORITHM_SHA256' },
      nonce: 'bm9uY2U=',
    });
    expect(result.textContent).toContain('SHA256-RSAPSS');
    expect(result.textContent).toContain('Bound');
  });

  it('verifies the held quote with its binding', async () => {
    const sent = stubControlPlane(
      routes({
        [QUOTE]: ok({ status: STATUS, quote: Q, channelBinding: 'Y2I=' }),
        [QUOTE_VERIFY]: ok({ status: STATUS, verified: true }),
      })
    );
    render(withControlPlane(<QuotesPage />));
    const card = await askForQuote();
    await screen.findByTestId('quote-result');

    fireEvent.change(within(card).getByLabelText('AK public key (PEM)'), { target: { value: 'UEVN' } });
    fireEvent.click(within(card).getByRole('button', { name: 'Verify quote' }));

    const verdict = await screen.findByTestId('quote-verdict');
    expect(verdict.textContent).toContain('Verified');
    const verifies = sent.filter((r) => r.path === '/api/v1/attestation/quote/verify');
    expect(verifies).toHaveLength(1);
    expect(verifies[0].body).toEqual({ quote: Q, akPublicKeyPem: 'UEVN', expectedNonce: 'bm9uY2U=', channelBinding: 'Y2I=' });
  });

  it('shows a failed verification and a refused quote', async () => {
    const r = routes({
      [QUOTE]: ok({ status: STATUS, quote: Q, channelBinding: 'Y2I=' }),
      [QUOTE_VERIFY]: ok({ status: STATUS, verified: false, message: 'nonce mismatch' }),
    });
    stubControlPlane(r);
    render(withControlPlane(<QuotesPage />));
    const card = await askForQuote();
    await screen.findByTestId('quote-result');

    fireEvent.change(within(card).getByLabelText('AK public key (PEM)'), { target: { value: 'UEVN' } });
    fireEvent.click(within(card).getByRole('button', { name: 'Verify quote' }));
    const verdict = await screen.findByTestId('quote-verdict');
    expect(verdict.textContent).toContain('Not verified: nonce mismatch');

    r[QUOTE] = refused(403, 'caller not admitted');
    fireEvent.click(within(card).getByRole('button', { name: 'Get quote' }));
    await waitFor(() => {
      const toasts = screen.getAllByTestId('toast');
      expect(toasts.some((t) => t.dataset.variant === 'destructive' && t.textContent?.includes('caller not admitted'))).toBe(true);
    });
    expect(screen.queryByTestId('quote-result')).toBeNull();
  });

  it('withholds get and verify quote the server does not offer', async () => {
    stubControlPlane(routes({ 'GET /api/v1/capabilities': caps([QUOTE, QUOTE_VERIFY]) }));
    render(withControlPlane(<QuotesPage />));
    const card = await screen.findByTestId('quote-verify');

    for (const [name, op] of [
      ['Get quote', QUOTE],
      ['Verify quote', QUOTE_VERIFY],
    ]) {
      const button = (await within(card).findByRole('button', { name })) as HTMLButtonElement;
      expect(button.getAttribute('data-capability-op')).toBe(op);
      await waitFor(() => expect(button.getAttribute('data-capability-enabled')).toBe('false'));
      expect(button.disabled).toBe(true);
      expect(button.getAttribute('title')).toBe('not-configured: attestation');
    }
  });

  it('parses the AK handle and PCR list', () => {
    expect(parseAkHandle('0x81010001')).toBe(2164326401);
    expect(parseAkHandle('')).toBeUndefined();
    expect(parseAkHandle('zz')).toBeNaN();
    expect(parsePcrIndices('0, 7,,23')).toEqual([0, 7, 23]);
    expect(parsePcrIndices(' ')).toBeUndefined();
    expect(parsePcrIndices('1,x')).toBeNull();
  });
});
