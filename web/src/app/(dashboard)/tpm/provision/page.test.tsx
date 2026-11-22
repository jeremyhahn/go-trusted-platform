import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import TPMProvisionPage from './page';

// #2068: the provisioning page reads the TPM's platform attributes and
// capabilities on mount, provisions with the checked keys, and clears the
// TPM only after the operator confirms; refusals reach the operator as
// destructive toasts carrying the server's message.

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const PLATFORM: Answer = ok({
  device: '/dev/tpmrm0',
  manufacturer: 'IBM',
  isFips: false,
  isSimulator: true,
  canSeal: true,
  pcrExtended: false,
  ek: { handle: 2164260865, algorithm: 'RSA' },
  srk: { handle: 2164260866, algorithm: 'RSA' },
});

const CAPABILITIES: Answer = ok({
  algorithms: ['RSA', 'ECC', 'SHA256'],
  commands: ['TPM2_Quote', 'TPM2_Clear'],
  eccCurves: ['NIST_P256'],
});

function stub(extra: Record<string, Answer> = {}) {
  return stubControlPlane({
    'GET /api/v1/tpm/platform': PLATFORM,
    'GET /api/v1/tpm/capabilities': CAPABILITIES,
    ...extra,
  });
}

async function renderPage() {
  render(withControlPlane(<TPMProvisionPage />));
  await screen.findByTestId('platform-device');
}

async function click(name: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name }));
  });
}

async function type(label: string, value: string) {
  await act(async () => {
    fireEvent.change(screen.getByLabelText(label), { target: { value } });
  });
}

async function toastText(text: string, variant?: string) {
  await waitFor(() => {
    const toasts = screen
      .queryAllByTestId('toast')
      .filter((t) => variant === undefined || t.getAttribute('data-variant') === variant);
    expect(toasts.some((t) => t.textContent?.includes(text))).toBe(true);
  });
  const toasts = await screen.findAllByTestId('toast');
  return toasts.map((t) => t.textContent ?? '').join('\n');
}

describe('TPMProvisionPage', () => {
  it('shows the platform attributes and the capabilities', async () => {
    stub();
    await renderPage();
    expect(screen.getByTestId('platform-device').textContent).toBe('/dev/tpmrm0');
    expect(screen.getByTestId('platform-simulator').textContent).toBe('Yes');
    expect(screen.getByTestId('platform-fips').textContent).toBe('No');
    expect(screen.getByTestId('platform-ek').textContent).toBe('0x81000001 (RSA)');
    expect(screen.getByTestId('platform-iak').textContent).toBe('not provisioned');
    expect((await screen.findByTestId('cap-counts')).textContent).toBe('3 algorithms, 2 commands, 1 ECC curves');
    expect(screen.getByTestId('cap-algorithms').textContent).toBe('RSA, ECC, SHA256');
  });

  it('shows a refused capabilities read', async () => {
    stub({ 'GET /api/v1/tpm/capabilities': refused(404, 'tpm: capabilities unavailable') });
    await renderPage();
    expect((await screen.findByTestId('capabilities-error')).textContent).toContain('capabilities unavailable');
    expect(screen.getByTestId('platform-device').textContent).toBe('/dev/tpmrm0');
  });

  it('provisions with the checked keys and re-reads the platform', async () => {
    const sent = stub({
      'POST /api/v1/tpm/provision': ok({
        status: { success: true, message: 'provisioned' },
        ekPublic: 'ZWs=',
        srkPublic: 'c3Jr',
      }),
    });
    await renderPage();
    await type('Endorsement password', 'e');
    await act(async () => {
      fireEvent.click(screen.getByRole('checkbox', { name: 'Create AK' }));
    });
    await click('Provision TPM');
    expect((await screen.findByTestId('provisioned-keys')).textContent).toBe('EK, SRK');
    const provision = sent.filter((s) => s.path === '/api/v1/tpm/provision');
    expect(provision).toHaveLength(1);
    expect(provision[0].body).toEqual({ endorsementPassword: 'e', createEk: true, createSrk: true, createAk: true });
    await toastText('TPM provisioned');
    await waitFor(() => expect(sent.filter((s) => s.path === '/api/v1/tpm/platform')).toHaveLength(2));
  });

  it('reports a refused provision', async () => {
    stub({ 'POST /api/v1/tpm/provision': refused(409, 'tpm: already provisioned') });
    await renderPage();
    await click('Provision TPM');
    await toastText('Provision failed', 'destructive');
    await toastText('already provisioned', 'destructive');
  });

  it('clears only after the confirm dialog', async () => {
    const sent = stub({
      'POST /api/v1/tpm/clear': ok({ status: { success: true, message: 'TPM cleared successfully' } }),
    });
    const clears = () => sent.filter((s) => s.path === '/api/v1/tpm/clear');
    await renderPage();
    await type('Lockout password', 'lockout');
    await click('Clear TPM…');
    expect(clears()).toHaveLength(0);
    expect(await screen.findByText('Clear the TPM?')).toBeTruthy();
    await click('Cancel');
    expect(clears()).toHaveLength(0);
    await waitFor(() => expect(screen.queryByText('Clear the TPM?')).toBeNull());
    await click('Clear TPM…');
    await screen.findByText('Clear the TPM?');
    await click('Clear');
    await waitFor(() => expect(clears()).toHaveLength(1));
    expect(clears()[0].body).toEqual({ ownerPassword: 'lockout', confirm: true });
    await toastText('TPM cleared');
  });

  it('reports a refused clear', async () => {
    stub({ 'POST /api/v1/tpm/clear': refused(403, 'tpm: lockout authorization failed') });
    await renderPage();
    await type('Lockout password', 'wrong');
    await click('Clear TPM…');
    await screen.findByText('Clear the TPM?');
    await click('Clear');
    await toastText('Clear failed', 'destructive');
    await toastText('lockout authorization failed', 'destructive');
  });
});
