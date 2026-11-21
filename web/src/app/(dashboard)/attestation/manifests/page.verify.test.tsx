import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import type { HostManifest } from 'trusted-platform-sdk';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import ManifestsPage from './page';

// #2038: the manifests page verifies a manifest (VerifyManifest) through
// useAttestationVerify and deletes one (DeleteManifest) after a confirm,
// through the SDK client.

const MANIFESTS = 'GET /api/v1/attestation/manifests';
const MANIFEST_VERIFY = 'POST /api/v1/attestation/manifests/verify';
const DELETE_M1 = 'DELETE /api/v1/attestation/manifests/m1';

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

const VERIFIED = {
  status: 'VERIFIED',
  signatureValid: true,
  merkleRootValid: true,
  nonceValid: true,
  timestampValid: true,
  hostAttestationValid: true,
  vmAttestationsValid: true,
  containerAttestationsValid: true,
  verifiedAt: '2026-11-20T10:05:00Z',
  errors: [] as string[],
};

function routes(extra: Record<string, Answer>): Record<string, Answer> {
  return { [MANIFESTS]: ok({ manifests: [M1, M2], total: 2 }), ...extra };
}

function hasToast(text: string, variant?: string): boolean {
  return screen
    .queryAllByTestId('toast')
    .some((t) => (variant ? t.dataset.variant === variant : true) && (t.textContent ?? '').includes(text));
}

describe('ManifestsPage verify and delete', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('verifies the selected manifest', async () => {
    const sent = stubControlPlane(routes({ [MANIFEST_VERIFY]: ok({ status: STATUS, result: VERIFIED }) }));
    render(withControlPlane(<ManifestsPage />));
    const card = await screen.findByTestId('manifest-actions');

    fireEvent.change(within(card).getByLabelText('Manifest'), { target: { value: 'm2' } });
    fireEvent.change(within(card).getByLabelText('Expected nonce'), { target: { value: 'bg==' } });
    fireEvent.click(await within(card).findByRole('button', { name: 'Verify manifest' }));

    const verdict = await screen.findByTestId('manifest-verdict');
    expect(verdict.textContent).toContain('VERIFIED');
    expect(verdict.textContent).toContain('No errors');
    const verifies = sent.filter((r) => r.path === '/api/v1/attestation/manifests/verify');
    expect(verifies).toHaveLength(1);
    expect(verifies[0].body).toEqual({ manifest: M2, expectedNonce: 'bg==' });
  });

  it('shows the verification errors and a refused verify', async () => {
    const r = routes({
      [MANIFEST_VERIFY]: ok({
        status: STATUS,
        result: { ...VERIFIED, status: 'FAILED', signatureValid: false, errors: ['signature does not match'] },
      }),
    });
    stubControlPlane(r);
    render(withControlPlane(<ManifestsPage />));
    const card = await screen.findByTestId('manifest-actions');

    fireEvent.click(await within(card).findByRole('button', { name: 'Verify manifest' }));
    const verdict = await screen.findByTestId('manifest-verdict');
    expect(verdict.textContent).toContain('FAILED');
    expect(verdict.textContent).toContain('signature does not match');

    r[MANIFEST_VERIFY] = refused(400, 'manifest is required');
    fireEvent.click(within(card).getByRole('button', { name: 'Verify manifest' }));
    await waitFor(() => expect(hasToast('manifest is required', 'destructive')).toBe(true));
  });

  it('deletes a manifest only after the confirm', async () => {
    const sent = stubControlPlane(routes({ [DELETE_M1]: ok({ status: STATUS }) }));
    render(withControlPlane(<ManifestsPage />));
    const card = await screen.findByTestId('manifest-actions');

    fireEvent.click(await within(card).findByRole('button', { name: 'Delete manifest' }));
    let dialog = await screen.findByRole('dialog');
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(sent.filter((r) => r.method === 'DELETE')).toHaveLength(0);

    fireEvent.click(await screen.findByRole('button', { name: 'Delete manifest' }));
    dialog = await screen.findByRole('dialog');
    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' }));

    await waitFor(() => expect(hasToast('Manifest deleted: m1')).toBe(true));
    const deletes = sent.filter((r) => r.method === 'DELETE');
    expect(deletes).toHaveLength(1);
    expect(deletes[0].path).toBe('/api/v1/attestation/manifests/m1');
    await waitFor(() =>
      expect(sent.filter((r) => r.method === 'GET' && r.path === '/api/v1/attestation/manifests')).toHaveLength(2)
    );
  });

  it('keeps the dialog open on a refused delete', async () => {
    stubControlPlane(routes({ [DELETE_M1]: refused(404, 'manifest m1 not found') }));
    render(withControlPlane(<ManifestsPage />));
    const card = await screen.findByTestId('manifest-actions');

    fireEvent.click(await within(card).findByRole('button', { name: 'Delete manifest' }));
    const dialog = await screen.findByRole('dialog');
    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' }));

    await waitFor(() => expect(hasToast('manifest m1 not found', 'destructive')).toBe(true));
    expect(within(screen.getByRole('dialog')).getByText('Delete manifest')).toBeTruthy();
  });
});
