import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import { ManifestVerifyButton } from './manifest-verify-button';

// #2038: VerifyManifest (POST /api/v1/attestation/manifests/verify) is sent
// through the real SDK client on client.attestation, with the manifest the
// control fetched or was given, and only when the server offers the route.

vi.mock('next/navigation', () => ({
  useParams: () => ({}),
  usePathname: () => '/attestation/verify',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const GET_OP = 'GET /api/v1/attestation/manifests/{id}';
const VERIFY_OP = 'POST /api/v1/attestation/manifests/verify';

const MANIFEST = {
  id: 'm-1',
  hostId: 'lab-node-1',
  nonce: 'bm9uY2U=',
  vms: [],
  containers: [],
  merkleRoot: 'cm9vdA==',
  signature: 'c2ln',
  signatureAlgorithm: 'ES256',
  version: '1',
  timestamp: '2026-11-01T00:00:00Z',
};

const RESULT = {
  status: 'VERIFIED',
  signatureValid: true,
  merkleRootValid: true,
  nonceValid: true,
  timestampValid: true,
  hostAttestationValid: true,
  vmAttestationsValid: true,
  containerAttestationsValid: true,
  verifiedAt: '2026-11-01T00:00:05Z',
  errors: [],
};

// The server's capabilities listing: the get and verify ops, verify off when off is set.
function caps(off = false): Answer {
  const capabilities = [
    { op: GET_OP, kind: 'route', enabled: true },
    off
      ? { op: VERIFY_OP, kind: 'route', enabled: false, reason: 'not-configured: attestation' }
      : { op: VERIFY_OP, kind: 'route', enabled: true },
  ];
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

function routes(extra: Record<string, Answer> = {}, off = false): Record<string, Answer> {
  return {
    'GET /api/v1/capabilities': caps(off),
    'GET /api/v1/attestation/manifests/m-1': ok({ manifest: MANIFEST }),
    'POST /api/v1/attestation/manifests/verify': ok({ status: { success: true, message: 'ok' }, result: RESULT }),
    ...extra,
  };
}

function manifestCalls(sent: { method: string; path: string; body: unknown }[]) {
  return sent.filter((r) => r.path.startsWith('/api/v1/attestation/manifests'));
}

async function enabledButton() {
  const button = await screen.findByRole('button', { name: 'Verify manifest' });
  await waitFor(() => expect(button.getAttribute('data-capability-enabled')).toBe('true'));
  return button;
}

// The live toast carrying text; toasts from an earlier case may still be listed.
async function toastWith(text: string) {
  return waitFor(() => {
    const found = screen.queryAllByTestId('toast').find((t) => t.textContent?.includes(text));
    expect(found).toBeTruthy();
    return found as HTMLElement;
  });
}

describe('ManifestVerifyButton', () => {
  it('verifies the manifest it fetched', async () => {
    const sent = stubControlPlane(routes());
    render(withControlPlane(<ManifestVerifyButton manifestId="m-1" />));

    fireEvent.click(await enabledButton());
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText('Verify manifest')).toBeTruthy();
    expect(within(dialog).queryByLabelText('Public key (PEM)')).toBeNull();
    expect(dialog.textContent).toContain('does not check the manifest signature');
    fireEvent.change(within(dialog).getByLabelText('Expected nonce'), { target: { value: 'bm9uY2U=' } });
    expect(manifestCalls(sent)).toHaveLength(0);

    fireEvent.click(within(dialog).getByRole('button', { name: 'Verify' }));
    const result = await screen.findByTestId('manifest-verify-result');
    expect(result.textContent).toContain('VERIFIED');

    const calls = manifestCalls(sent);
    expect(calls.map((r) => `${r.method} ${r.path}`)).toEqual([
      'GET /api/v1/attestation/manifests/m-1',
      'POST /api/v1/attestation/manifests/verify',
    ]);
    const body = calls[1].body as { manifest: { id: string }; expectedNonce?: string; publicKeyPem?: string };
    expect(body.manifest.id).toBe('m-1');
    expect(body.expectedNonce).toBe('bm9uY2U=');
    expect(body.publicKeyPem).toBeUndefined();
    // RESULT says signatureValid: true, but the server checks no signature: the row must not echo it.
    const signature = screen.getByTestId('manifest-verify-check-signatureValid').textContent ?? '';
    expect(signature).toContain('Signature');
    expect(signature).toContain('not checked');
    expect(signature).not.toContain('valid');
    expect(screen.getByTestId('manifest-verify-check-containerAttestationsValid').textContent).not.toContain('invalid');
  });

  it('offers no public key, since the server refuses one with ErrAttestationManifestSignatureUnchecked', async () => {
    const sent = stubControlPlane(routes());
    render(withControlPlane(<ManifestVerifyButton manifestId="m-1" manifest={MANIFEST} />));

    fireEvent.click(await enabledButton());
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).queryByLabelText('Public key (PEM)')).toBeNull();
    expect(within(dialog).queryByRole('textbox', { name: /public key/i })).toBeNull();
    fireEvent.click(within(dialog).getByRole('button', { name: 'Verify' }));
    await screen.findByTestId('manifest-verify-result');

    const calls = manifestCalls(sent);
    expect(calls).toHaveLength(1);
    const body = calls[0].body as Record<string, unknown>;
    expect('publicKeyPem' in body).toBe(false);
  });

  it('uses the manifest it was given without fetching', async () => {
    const sent = stubControlPlane(routes());
    render(withControlPlane(<ManifestVerifyButton manifestId="m-1" manifest={MANIFEST} />));

    fireEvent.click(await enabledButton());
    fireEvent.click(await screen.findByRole('button', { name: 'Verify' }));
    await screen.findByTestId('manifest-verify-result');

    const calls = manifestCalls(sent);
    expect(calls.map((r) => `${r.method} ${r.path}`)).toEqual(['POST /api/v1/attestation/manifests/verify']);
    const body = calls[0].body as { manifest: { id: string; hostId: string }; expectedNonce?: string };
    expect(body.manifest.id).toBe('m-1');
    expect(body.manifest.hostId).toBe('lab-node-1');
    expect(body.expectedNonce).toBeUndefined();
  });

  it('lists the verifier errors of a failed result', async () => {
    const failed = { ...RESULT, status: 'FAILED', signatureValid: false, errors: ['signature mismatch'] };
    stubControlPlane(
      routes({
        'POST /api/v1/attestation/manifests/verify': ok({ status: { success: true, message: 'ok' }, result: failed }),
      }),
    );
    render(withControlPlane(<ManifestVerifyButton manifestId="m-1" />));

    fireEvent.click(await enabledButton());
    fireEvent.click(await screen.findByRole('button', { name: 'Verify' }));
    const result = await screen.findByTestId('manifest-verify-result');
    expect(result.textContent).toContain('FAILED');
    expect(screen.getByTestId('manifest-verify-errors').textContent).toContain('signature mismatch');
    // The signature row reads the same whatever signatureValid says.
    expect(screen.getByTestId('manifest-verify-check-signatureValid').textContent).toContain('not checked');
    const merkle = screen.getByTestId('manifest-verify-check-merkleRootValid').textContent ?? '';
    expect(merkle).toContain('not checked');
    expect(merkle).not.toContain('valid');
  });

  it('shows the checks the server does not make as not checked', async () => {
    // RESULT says every check passed, and a failed variant says they failed:
    // the rows for the server's placeholder checks read the same either way.
    for (const value of [true, false]) {
      const answer = {
        ...RESULT,
        merkleRootValid: value,
        hostAttestationValid: value,
        vmAttestationsValid: value,
        containerAttestationsValid: value,
      };
      stubControlPlane(
        routes({
          'POST /api/v1/attestation/manifests/verify': ok({ status: { success: true, message: 'ok' }, result: answer }),
        }),
      );
      render(withControlPlane(<ManifestVerifyButton manifestId="m-1" manifest={MANIFEST} />));

      fireEvent.click(await enabledButton());
      fireEvent.click(await screen.findByRole('button', { name: 'Verify' }));
      await screen.findByTestId('manifest-verify-result');
      for (const [name, label] of [
        ['merkleRootValid', 'Merkle root'],
        ['hostAttestationValid', 'Host attestation'],
        ['vmAttestationsValid', 'VM attestations'],
        ['containerAttestationsValid', 'Container attestations'],
      ]) {
        const row = screen.getByTestId(`manifest-verify-check-${name}`).textContent ?? '';
        expect(row).toContain(label);
        expect(row).toContain('not checked');
        expect(row).not.toContain('valid');
      }
      for (const name of ['nonceValid', 'timestampValid']) {
        const row = screen.getByTestId(`manifest-verify-check-${name}`).textContent ?? '';
        expect(row).toContain('valid');
        expect(row).not.toContain('invalid');
        expect(row).not.toContain('not checked');
      }
      cleanup();
      vi.unstubAllGlobals();
    }
  });

  it('styles the wire VERIFIED status as success', async () => {
    for (const [status, verified] of [
      ['MANIFEST_VERIFICATION_STATUS_VERIFIED', 'true'],
      ['MANIFEST_VERIFICATION_STATUS_FAILED', 'false'],
    ]) {
      stubControlPlane(
        routes({
          'POST /api/v1/attestation/manifests/verify': ok({
            status: { success: true, message: 'ok' },
            result: { ...RESULT, status },
          }),
        }),
      );
      render(withControlPlane(<ManifestVerifyButton manifestId="m-1" manifest={MANIFEST} />));

      fireEvent.click(await enabledButton());
      fireEvent.click(await screen.findByRole('button', { name: 'Verify' }));
      await screen.findByTestId('manifest-verify-result');
      const badge = screen.getByTestId('manifest-verify-status');
      expect(badge.textContent).toBe(status);
      expect(badge.getAttribute('data-verified')).toBe(verified);
      cleanup();
      vi.unstubAllGlobals();
    }
  });

  it('withholds the control the server does not offer', async () => {
    const sent = stubControlPlane(routes({}, true));
    render(withControlPlane(<ManifestVerifyButton manifestId="m-1" />));

    const button = await screen.findByRole('button', { name: 'Verify manifest' });
    await waitFor(() => expect(button.getAttribute('data-capability-enabled')).toBe('false'));
    expect((button as HTMLButtonElement).disabled).toBe(true);
    expect(button.getAttribute('title')).toBe('not-configured: attestation');
    fireEvent.click(button);
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(sent.filter((r) => r.path === '/api/v1/attestation/manifests/verify')).toHaveLength(0);
  });

  it('shows a refused verify as a destructive toast', async () => {
    stubControlPlane(routes({ 'POST /api/v1/attestation/manifests/verify': refused(400, 'manifest is required') }));
    render(withControlPlane(<ManifestVerifyButton manifestId="m-1" />));

    fireEvent.click(await enabledButton());
    fireEvent.click(await screen.findByRole('button', { name: 'Verify' }));
    const toast = await toastWith('manifest is required');
    expect(toast.textContent).toContain('Verification failed');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
  });

  it('says that inspecting a manifest restores no quarantined device', async () => {
    stubControlPlane(routes());
    render(withControlPlane(<ManifestVerifyButton manifestId="m-1" manifest={MANIFEST} />));

    fireEvent.click(await enabledButton());
    await screen.findByRole('button', { name: 'Verify' });
    // service.go dispatches only failures from VerifyManifest: an inspection is not a verdict (#2038).
    expect(screen.getByText(/does not restore a quarantined device/)).toBeTruthy();
  });
});
