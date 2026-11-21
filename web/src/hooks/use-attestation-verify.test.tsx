import { act, cleanup, renderHook } from '@testing-library/react';
import type { ReactNode } from 'react';
import type { HostManifest } from 'trusted-platform-sdk';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import { quoteVerdictLabel, useAttestationVerify } from './use-attestation-verify';

// #2038: the verify hook reaches VerifyManifest, GetAttestationQuote and
// VerifyAttestationQuote through the SDK AttestationService (no hand-written
// fetch); quoteAndVerify sends the quote back with its nonce and binding.

const MANIFEST_VERIFY = 'POST /api/v1/attestation/manifests/verify';
const QUOTE = 'POST /api/v1/attestation/quote';
const QUOTE_VERIFY = 'POST /api/v1/attestation/quote/verify';

const Q = { quoteData: 'cQ==', signature: 'c2ln', signatureAlgorithm: 'SHA256-RSAPSS', pcrValues: [], nonce: 'bg==' };
const STATUS = { success: true, message: '' };

function renderVerify() {
  return renderHook(() => useAttestationVerify(), {
    wrapper: ({ children }: { children: ReactNode }) => withControlPlane(children),
  });
}

describe('useAttestationVerify', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('verifies a manifest through POST /manifests/verify', async () => {
    const routes: Record<string, Answer> = {
      [MANIFEST_VERIFY]: ok({ status: STATUS, result: { status: 'VALID', signatureValid: true, errors: [] } }),
    };
    const sent = stubControlPlane(routes);
    const { result } = renderVerify();
    let res: Awaited<ReturnType<typeof result.current.verifyManifest>> | undefined;
    await act(async () => {
      res = await result.current.verifyManifest({
        manifest: { id: 'm1' } as unknown as HostManifest,
        expectedNonce: 'bg==',
      });
    });
    expect(res?.data?.result?.signatureValid).toBe(true);
    expect(sent).toEqual([
      {
        method: 'POST',
        path: '/api/v1/attestation/manifests/verify',
        body: { manifest: { id: 'm1' }, expectedNonce: 'bg==' },
      },
    ]);
  });

  it('asks for a quote through POST /quote', async () => {
    const sent = stubControlPlane({ [QUOTE]: ok({ status: STATUS, quote: Q, channelBinding: 'Y2I=' }) });
    const { result } = renderVerify();
    let res: Awaited<ReturnType<typeof result.current.getQuote>> | undefined;
    await act(async () => {
      res = await result.current.getQuote({ config: { akHandle: 2164260865, pcrIndices: [0, 7] }, nonce: 'bg==' });
    });
    expect(res?.data?.quote?.signatureAlgorithm).toBe('SHA256-RSAPSS');
    expect(sent).toHaveLength(1);
    expect(sent[0].path).toBe('/api/v1/attestation/quote');
    expect(sent[0].body).toEqual({ config: { akHandle: 2164260865, pcrIndices: [0, 7] }, nonce: 'bg==' });
  });

  it('quotes then verifies with the returned channel binding', async () => {
    const sent = stubControlPlane({
      [QUOTE]: ok({ status: STATUS, quote: Q, channelBinding: 'Y2I=' }),
      [QUOTE_VERIFY]: ok({ status: STATUS, verified: true }),
    });
    const { result } = renderVerify();
    let res: Awaited<ReturnType<typeof result.current.quoteAndVerify>> | undefined;
    await act(async () => {
      res = await result.current.quoteAndVerify({ config: { pcrIndices: [7] }, nonce: 'bg==', akPublicKeyPem: 'UEVN' });
    });
    expect(sent.map((s) => s.path)).toEqual(['/api/v1/attestation/quote', '/api/v1/attestation/quote/verify']);
    expect(sent[1].body).toEqual({ quote: Q, akPublicKeyPem: 'UEVN', expectedNonce: 'bg==', channelBinding: 'Y2I=' });
    expect(quoteVerdictLabel(res?.verify?.data)).toBe('Verified');
  });

  it('stops after a refused quote', async () => {
    const sent = stubControlPlane({
      [QUOTE]: refused(403, 'caller not admitted'),
      [QUOTE_VERIFY]: ok({ status: STATUS, verified: true }),
    });
    const { result } = renderVerify();
    let res: Awaited<ReturnType<typeof result.current.quoteAndVerify>> | undefined;
    await act(async () => {
      res = await result.current.quoteAndVerify({ config: { pcrIndices: [7] }, nonce: 'bg==', akPublicKeyPem: 'UEVN' });
    });
    expect(res?.quote.success).toBe(false);
    expect(res?.quote.error?.status).toBe(403);
    expect(res?.verify).toBeUndefined();
    expect(sent).toHaveLength(1);
  });

  it('labels a failed verification', () => {
    expect(quoteVerdictLabel({ status: STATUS, verified: false, message: 'nonce mismatch' })).toBe(
      'Not verified: nonce mismatch'
    );
    expect(quoteVerdictLabel({ status: STATUS, verified: false })).toBe('Not verified');
    expect(quoteVerdictLabel(undefined)).toBe('Unknown');
  });

  it('surfaces a refused manifest verify', async () => {
    stubControlPlane({ [MANIFEST_VERIFY]: refused(400, 'manifest is required') });
    const { result } = renderVerify();
    let res: Awaited<ReturnType<typeof result.current.verifyManifest>> | undefined;
    await act(async () => {
      res = await result.current.verifyManifest({ manifest: { id: 'm1' } as unknown as HostManifest });
    });
    expect(res?.success).toBe(false);
    expect(res?.error?.status).toBe(400);
    expect(res?.error?.message).toBe('manifest is required');
  });
});
