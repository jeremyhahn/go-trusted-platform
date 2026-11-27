import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ReactNode } from 'react';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { base64ToHex, textToBase64, useTPMOps } from './use-tpm-ops';

// #2069: useTPMOps drives PCR extend, MakeCredential, ActivateCredential and
// GetRandom through the SDK client, and its helpers convert text and bytes.

const EXTEND = 'POST /api/v1/tpm/pcrs/extend';
const MAKE = 'POST /api/v1/tpm/make-credential';
const ACTIVATE = 'POST /api/v1/tpm/activate-credential';
const RANDOM = 'POST /api/v1/tpm/random';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function renderTPMOps() {
  return renderHook(() => useTPMOps(), {
    wrapper: ({ children }: { children: ReactNode }) => withControlPlane(children),
  });
}

describe('useTPMOps', () => {
  it('extends a PCR through POST /tpm/pcrs/extend with the bank lowercased', async () => {
    const sent = stubControlPlane({ [EXTEND]: ok({}) });
    const { result } = renderTPMOps();
    const data = textToBase64('measure');

    await act(() => result.current.extendPCR.mutateAsync({ index: 7, hashAlg: 'SHA256', data }));

    expect(sent).toContainEqual({
      method: 'POST',
      path: '/api/v1/tpm/pcrs/extend',
      body: { index: 7, hashAlg: 'sha256', data },
    });
    expect(result.current.extendPCR.isSuccess).toBe(true);
  });

  it('makes a credential through POST /tpm/make-credential and answers the blob', async () => {
    const answer = { credentialBlob: 'YmxvYg==', encryptedSecret: 'c2VjcmV0', secret: 'czM=' };
    const sent = stubControlPlane({ [MAKE]: ok(answer) });
    const { result } = renderTPMOps();

    let got: unknown;
    await act(async () => {
      got = await result.current.makeCredential.mutateAsync({ akName: 'YWtuYW1l', secret: 'czM=' });
    });

    expect(sent).toContainEqual({
      method: 'POST',
      path: '/api/v1/tpm/make-credential',
      body: { akName: 'YWtuYW1l', secret: 'czM=' },
    });
    expect((got as { credentialBlob: string }).credentialBlob).toBe('YmxvYg==');
    await waitFor(() => expect(result.current.makeCredential.data?.credentialBlob).toBe('YmxvYg=='));
  });

  it('activates a credential through POST /tpm/activate-credential and answers the secret', async () => {
    const sent = stubControlPlane({ [ACTIVATE]: ok({ secret: 'czM=' }) });
    const { result } = renderTPMOps();

    let got: unknown;
    await act(async () => {
      got = await result.current.activateCredential.mutateAsync({
        credentialBlob: 'YmxvYg==',
        encryptedSecret: 'c2VjcmV0',
      });
    });

    expect(sent).toContainEqual({
      method: 'POST',
      path: '/api/v1/tpm/activate-credential',
      body: { credentialBlob: 'YmxvYg==', encryptedSecret: 'c2VjcmV0' },
    });
    expect((got as { secret: string }).secret).toBe('czM=');
    await waitFor(() => expect(result.current.activateCredential.data?.secret).toBe('czM='));
  });

  it('draws random bytes through POST /tpm/random', async () => {
    const sent = stubControlPlane({ [RANDOM]: ok({ randomBytes: 'AAECAwQFBgcICQoLDA0ODw==' }) });
    const { result } = renderTPMOps();

    await act(() => result.current.getRandom.mutateAsync({ numBytes: 16 }));

    expect(sent).toContainEqual({ method: 'POST', path: '/api/v1/tpm/random', body: { numBytes: 16 } });
    await waitFor(() => expect(result.current.getRandom.data?.randomBytes).toBe('AAECAwQFBgcICQoLDA0ODw=='));
  });

  it('leaves a refused mutation with its error set and no data', async () => {
    stubControlPlane({ [RANDOM]: refused(503, 'tpm unavailable') });
    const { result } = renderTPMOps();

    await act(async () => {
      await expect(result.current.getRandom.mutateAsync({ numBytes: 16 })).rejects.toBeTruthy();
    });

    await waitFor(() => expect(result.current.getRandom.isError).toBe(true));
    expect(result.current.getRandom.error).toBeDefined();
    expect(result.current.getRandom.data).toBeUndefined();
  });
});

describe('use-tpm-ops helpers', () => {
  it('textToBase64 encodes UTF-8 text', () => {
    expect(textToBase64('hello')).toBe('aGVsbG8=');
  });

  it('base64ToHex answers lower-case hex, and empty for an invalid input', () => {
    expect(base64ToHex('AAEC')).toBe('000102');
    expect(base64ToHex('!!')).toBe('');
  });
});
