import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { TPMCertifyCard, parsePersistentHandle } from './tpm-certify-card';

// #2068: the certify card asks the TPM to certify, under its IAK, a key at a
// persistent handle (POST /api/v1/tpm/certify on the API client) and shows the
// signed result; a refusal reaches the operator verbatim as a destructive toast.

const CERTIFY = 'POST /api/v1/tpm/certify';

function type(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

async function click(name: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name }));
  });
}

describe('TPMCertifyCard Certify', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('certifies a key with a nonce', async () => {
    const sent = stubControlPlane({
      [CERTIFY]: ok({
        certifyInfo: 'AQID',
        signature: 'BAUG',
        signatureAlgorithm: 'SHA256-RSAPSS',
        nonce: 'bm9uY2U=',
      }),
    });
    render(withControlPlane(<TPMCertifyCard />));
    type('Key handle', '0x81000001');
    type('Nonce (text)', 'nonce');
    await click('Certify');

    const toast = await screen.findByText('Key certified: signed under SHA256-RSAPSS');
    expect(toast.getAttribute('data-variant')).toBe('success');
    const posts = sent.filter((r) => r.method === 'POST' && r.path === '/api/v1/tpm/certify');
    expect(posts).toHaveLength(1);
    expect(posts[0].body).toEqual({ keyHandle: 2164260865, nonce: 'bm9uY2U=' });

    const result = screen.getByTestId('tpm-certify-result');
    expect(result.textContent).toContain('SHA256-RSAPSS');
    expect(result.textContent).toContain('6e6f6e6365');
    expect(result.textContent).toContain('010203');
  });

  it('sends the key password', async () => {
    const sent = stubControlPlane({ [CERTIFY]: ok({ signatureAlgorithm: 'SHA256-RSAPSS' }) });
    render(withControlPlane(<TPMCertifyCard />));
    type('Key handle', '0x81000002');
    type('Key password', 'pw');
    await click('Certify');

    await screen.findByText('Key certified: signed under SHA256-RSAPSS');
    const posts = sent.filter((r) => r.method === 'POST');
    expect(posts).toHaveLength(1);
    expect(posts[0].body).toEqual({ keyHandle: 2164260866, keyPassword: 'pw' });
  });

  it('refuses a non-persistent handle without a request', async () => {
    const sent = stubControlPlane({ [CERTIFY]: ok({}) });
    render(withControlPlane(<TPMCertifyCard />));
    type('Key handle', '0x80000001');
    await click('Certify');

    const toast = await screen.findByText(
      'Invalid handle: a persistent handle is 0x81000000-0x81FFFFFF'
    );
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(sent.filter((r) => r.method === 'POST')).toHaveLength(0);
  });

  it('shows a refusal verbatim', async () => {
    stubControlPlane({ [CERTIFY]: refused(404, 'certify: no key at handle 0x81000009') });
    render(withControlPlane(<TPMCertifyCard />));
    type('Key handle', '0x81000009');
    await click('Certify');

    const toast = await screen.findByText('Certify failed: certify: no key at handle 0x81000009');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    await waitFor(() => expect(screen.queryByTestId('tpm-certify-result')).toBeNull());
  });

  it('parses persistent handles', () => {
    expect(parsePersistentHandle('0x81FFFFFF')).toBe(2181038079);
    expect(parsePersistentHandle('2164260864')).toBe(2164260864);
    expect(Number.isNaN(parsePersistentHandle(''))).toBe(true);
    expect(Number.isNaN(parsePersistentHandle('0x82000000'))).toBe(true);
    expect(Number.isNaN(parsePersistentHandle('abc'))).toBe(true);
  });
});
