import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import { VMAttestCard } from './vm-attest-card';

// #2044: the VM detail page's Attest VM control sends AttestVM through the SDK
// client with a fresh nonce, behind the server's capability gate; the quote's
// PCR values are shown, a refusal reaches the operator as a destructive toast.

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const ATTEST_OP = 'POST /api/v1/compute/vms/{id}/attest';
const ATTEST_PATH = 'POST /api/v1/compute/vms/vm-1/attest';

function caps(off: string[] = []): Answer {
  const capabilities = [ATTEST_OP].map((op) =>
    off.includes(op)
      ? { op, kind: 'route', enabled: false, reason: 'not-configured: compute' }
      : { op, kind: 'route', enabled: true },
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

function attested(): Answer {
  return ok({
    status: { success: true, message: 'attested' },
    quote: 'cXVvdGU=',
    signature: 'c2ln',
    akPublic: 'QUtQVUJMSUNLRVlCWVRFU0FLUFVCTElDS0VZQllURVM=',
    signatureAlgorithm: 'SHA256-RSAPSS',
    pcrValues: [{ index: 0, bank: 'PCR_BANK_SHA256', value: 'abcdef0123' }],
  });
}

async function clickAttest() {
  await waitFor(() => {
    expect((screen.getByRole('button', { name: 'Attest VM' }) as HTMLButtonElement).disabled).toBe(false);
  });
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Attest VM' }));
  });
}

describe('VMAttestCard', () => {
  it('attests the VM with a fresh base64 nonce and shows the PCR values', async () => {
    const sent = stubControlPlane({ 'GET /api/v1/capabilities': caps(), [ATTEST_PATH]: attested() });
    render(withControlPlane(<VMAttestCard vmId="vm-1" />));

    await clickAttest();

    const result = await screen.findByTestId('vm-attest-result');
    const post = sent.find((r) => r.method === 'POST' && r.path === '/api/v1/compute/vms/vm-1/attest');
    expect(post).toBeDefined();
    const body = post?.body as { vmId?: string; nonce?: string };
    expect(body.vmId).toBe('vm-1');
    expect(body.nonce).toMatch(/^[A-Za-z0-9+/]+=*$/);
    expect(atob(body.nonce ?? '').length).toBe(32);

    expect(result.textContent).toContain('SHA256-RSAPSS');
    const row = screen.getByRole('row', { name: /abcdef0123/ });
    expect(row.textContent).toContain('0');
    expect(row.textContent).toContain('PCR_BANK_SHA256');
  });

  it('shows a refused attestation as a destructive toast', async () => {
    stubControlPlane({ 'GET /api/v1/capabilities': caps(), [ATTEST_PATH]: refused(409, 'no ak') });
    render(withControlPlane(<VMAttestCard vmId="vm-1" />));

    await clickAttest();

    await waitFor(() => {
      const toast = screen
        .getAllByTestId('toast')
        .find((t) => t.getAttribute('data-variant') === 'destructive');
      expect(toast?.textContent).toContain('Attestation failed');
      expect(toast?.textContent).toContain('no ak');
    });
    expect(screen.queryByTestId('vm-attest-result')).toBeNull();
  });

  it('withholds Attest VM when the server does not offer it', async () => {
    const sent = stubControlPlane({ 'GET /api/v1/capabilities': caps([ATTEST_OP]), [ATTEST_PATH]: attested() });
    render(withControlPlane(<VMAttestCard vmId="vm-1" />));

    await waitFor(() => {
      const attest = screen.getByRole('button', { name: 'Attest VM' }) as HTMLButtonElement;
      expect(attest.getAttribute('data-capability-enabled')).toBe('false');
      expect(attest.disabled).toBe(true);
      expect(attest.title).toBe('not-configured: compute');
    });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Attest VM' }));
    });
    expect(sent.some((r) => r.method === 'POST')).toBe(false);
  });
});
