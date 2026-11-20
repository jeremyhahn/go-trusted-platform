import { act, renderHook } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

interface Deferred {
  id: string;
  resolve: (value: unknown) => void;
}

const calls = vi.hoisted(() => ({
  get: [] as Deferred[],
  metrics: [] as Deferred[],
}));

const compute = vi.hoisted(() => ({
  getContainer: (id: string) =>
    new Promise((resolve) => {
      calls.get.push({ id, resolve });
    }),
  getContainerMetrics: (id: string) =>
    new Promise((resolve) => {
      calls.metrics.push({ id, resolve });
    }),
  execContainer: () => Promise.resolve({ success: true, data: {} }),
  attestContainer: () => Promise.resolve({ success: true, data: {} }),
  attestVM: vi.fn(),
  verifyVMAttestation: vi.fn(),
}));

vi.mock('trusted-platform-sdk', async (importOriginal) => ({
  ...(await importOriginal<typeof import('trusted-platform-sdk')>()),
  useCompute: () => compute,
}));

import { splitCommand, useContainerOps, useVMAttestationVerify } from './use-container-ops';

function settle(list: Deferred[], id: string, value: unknown): void {
  const i = list.findIndex((d) => d.id === id);
  if (i < 0) throw new Error(`no pending request for ${id}`);
  const [d] = list.splice(i, 1);
  d.resolve(value);
}

const containerOf = (id: string) => ({ success: true, data: { container: { id, name: id } } });
const metricsOf = (id: string) => ({ success: true, data: { metrics: { containerId: id } } });

afterEach(() => {
  calls.get.length = 0;
  calls.metrics.length = 0;
});

describe('useContainerOps across a container change', () => {
  it("drops container A's responses that settle after B's", async () => {
    const { result, rerender } = renderHook(({ id }) => useContainerOps(id), {
      initialProps: { id: 'a' },
    });
    rerender({ id: 'b' });

    await act(async () => {
      settle(calls.get, 'b', containerOf('b'));
      settle(calls.metrics, 'b', metricsOf('b'));
    });
    await act(async () => {
      settle(calls.get, 'a', containerOf('a'));
      settle(calls.metrics, 'a', metricsOf('a'));
    });

    expect(result.current.container).toEqual({ id: 'b', name: 'b' });
    expect(result.current.metrics).toEqual({ containerId: 'b' });
  });

  it("drops a refresh of A that settles after the hook moved to B", async () => {
    const { result, rerender } = renderHook(({ id }) => useContainerOps(id), {
      initialProps: { id: 'a' },
    });
    await act(async () => {
      settle(calls.get, 'a', containerOf('a'));
      settle(calls.metrics, 'a', metricsOf('a'));
    });
    const refreshA = result.current.refresh;
    const refreshMetricsA = result.current.refreshMetrics;
    let pendingA: Promise<unknown> = Promise.resolve();
    act(() => {
      pendingA = Promise.all([refreshA(), refreshMetricsA()]);
    });

    rerender({ id: 'b' });
    // B has not loaded: A's container must not show as B's.
    expect(result.current.container).toBeNull();
    expect(result.current.metrics).toBeNull();

    await act(async () => {
      settle(calls.get, 'b', containerOf('b'));
      settle(calls.metrics, 'b', metricsOf('b'));
    });
    await act(async () => {
      settle(calls.get, 'a', { success: false, error: { message: 'gone' } });
      settle(calls.metrics, 'a', metricsOf('a'));
      await pendingA;
    });

    expect(result.current.container).toEqual({ id: 'b', name: 'b' });
    expect(result.current.metrics).toEqual({ containerId: 'b' });
    expect(result.current.error).toBeNull();
  });
});

describe('useVMAttestationVerify', () => {
  const quote = {
    quote: 'cXVvdGU=',
    signature: 'c2ln',
    signatureAlgorithm: 'ECDSA_P256_SHA256',
  };

  afterEach(() => {
    compute.attestVM.mockReset();
    compute.verifyVMAttestation.mockReset();
  });

  it('sends a fresh nonce on every call and passes the quote on', async () => {
    compute.attestVM.mockResolvedValue({ success: true, data: quote });
    compute.verifyVMAttestation.mockResolvedValue({ success: true, data: { verified: true } });
    const { result } = renderHook(() => useVMAttestationVerify('vm-1'));

    await expect(result.current()).resolves.toEqual({ verified: true });
    await expect(result.current()).resolves.toEqual({ verified: true });

    expect(compute.attestVM).toHaveBeenCalledTimes(2);
    const [first, second] = compute.attestVM.mock.calls.map(([req]) => req);
    expect(first.vmId).toBe('vm-1');
    expect(second.vmId).toBe('vm-1');
    expect(first.nonce).toBeTruthy();
    expect(second.nonce).not.toBe(first.nonce);

    expect(compute.verifyVMAttestation).toHaveBeenCalledTimes(2);
    expect(compute.verifyVMAttestation.mock.calls[0][0]).toEqual({
      vmId: 'vm-1',
      nonce: first.nonce,
      ...quote,
    });
    expect(compute.verifyVMAttestation.mock.calls[1][0]).toEqual({
      vmId: 'vm-1',
      nonce: second.nonce,
      ...quote,
    });
  });

  it('rejects and never verifies when attestation fails', async () => {
    compute.attestVM.mockResolvedValue({ success: false, error: { message: 'no tpm' } });
    const { result } = renderHook(() => useVMAttestationVerify('vm-1'));

    await expect(result.current()).rejects.toThrow('no tpm');
    expect(compute.verifyVMAttestation).not.toHaveBeenCalled();
  });

  it('rejects when verification fails', async () => {
    compute.attestVM.mockResolvedValue({ success: true, data: quote });
    compute.verifyVMAttestation.mockResolvedValue({
      success: false,
      error: { message: 'bad quote' },
    });
    const { result } = renderHook(() => useVMAttestationVerify('vm-1'));

    await expect(result.current()).rejects.toThrow('bad quote');
  });
});

describe('splitCommand', () => {
  it('splits plain words on whitespace', () => {
    expect(splitCommand('  ls   -la /  ')).toEqual(['ls', '-la', '/']);
  });

  it('keeps a single-quoted script as one argument', () => {
    expect(splitCommand("sh -c 'echo hello'")).toEqual(['sh', '-c', 'echo hello']);
  });

  it('keeps double-quoted spaces and empty quoted arguments', () => {
    expect(splitCommand('echo "a b" ""')).toEqual(['echo', 'a b', '']);
  });

  it('honours backslash escapes outside quotes', () => {
    expect(splitCommand('echo a\\ b')).toEqual(['echo', 'a b']);
  });

  it('honours \\" and \\\\ inside double quotes', () => {
    expect(splitCommand('echo "say \\"hi\\" \\\\ ok"')).toEqual(['echo', 'say "hi" \\ ok']);
  });

  it('treats single-quoted text literally', () => {
    expect(splitCommand("echo 'a\\b \"c\"'")).toEqual(['echo', 'a\\b "c"']);
  });

  it('joins adjacent quoted and plain parts into one argument', () => {
    expect(splitCommand(`a'b c'"d"e`)).toEqual(['ab cde']);
  });

  it('returns no arguments for a blank line', () => {
    expect(splitCommand('   ')).toEqual([]);
  });

  it('throws on an unterminated quote', () => {
    expect(() => splitCommand("sh -c 'echo")).toThrow(/unterminated/i);
    expect(() => splitCommand('echo "a')).toThrow(/unterminated/i);
  });
});
