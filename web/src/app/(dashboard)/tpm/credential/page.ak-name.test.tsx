import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import TPMCredentialPage from './page';

// #2069: the credential page's "Use attestation key" control fills the AK
// name from GetAK through the SDK, gated on GET /api/v1/tpm/ak; a GetAK
// answer without a name says so, and a refusal reaches the operator as a
// destructive toast carrying the server's reason.

const AK_OP = 'GET /api/v1/tpm/ak';
const AK_REASON = 'not-configured: tpm';
const OPS = [
  'POST /api/v1/tpm/pcrs/extend',
  'POST /api/v1/tpm/make-credential',
  'POST /api/v1/tpm/activate-credential',
  'POST /api/v1/tpm/random',
  AK_OP,
];

function caps(off: string[] = []): Answer {
  return ok({
    capabilities: OPS.map((op) =>
      off.includes(op) ? { op, kind: 'route', enabled: false, reason: AK_REASON } : { op, kind: 'route', enabled: true }
    ),
  });
}

const CAPS_ON = caps();

/** Renders the page and waits for the capability gate to read the server's capabilities. */
async function renderPage() {
  render(withControlPlane(<TPMCredentialPage />));
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Get Random' }).getAttribute('data-capability-enabled')).toBe('true')
  );
}

function inputOf(label: string): HTMLInputElement {
  return screen.getByLabelText(label) as HTMLInputElement;
}

async function click(name: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name }));
  });
}

describe('TPMCredentialPage AK name from GetAK', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('fills the AK name from the GetAK answer', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/capabilities': CAPS_ON,
      [AK_OP]: ok({ publicKey: 'cGs=', handle: 2164260865, algorithm: 'RSA', name: 'AAuAAQ==' }),
    });
    await renderPage();

    await click('Use attestation key');

    await waitFor(() => expect(inputOf('AK name (base64)').value).toBe('AAuAAQ=='));
    expect(sent.some((r) => r.method === 'GET' && r.path === '/api/v1/tpm/ak')).toBe(true);
    expect(screen.queryByTestId('ak-name-missing')).toBeNull();
  });

  it('says so when the GetAK answer carries no AK name', async () => {
    stubControlPlane({
      'GET /api/v1/capabilities': CAPS_ON,
      [AK_OP]: ok({ publicKey: 'cGs=', handle: 2164260865, algorithm: 'RSA' }),
    });
    await renderPage();

    await click('Use attestation key');

    await screen.findByTestId('ak-name-missing');
    expect(inputOf('AK name (base64)').value).toBe('');
  });

  it('withholds Use attestation key when the server does not offer GET /api/v1/tpm/ak', async () => {
    stubControlPlane({ 'GET /api/v1/capabilities': caps([AK_OP]) });
    await renderPage();

    const button = screen.getByRole('button', { name: 'Use attestation key' });
    expect(button.getAttribute('data-capability-enabled')).toBe('false');
    expect(button.hasAttribute('disabled')).toBe(true);
    expect(button.getAttribute('title')).toBe(AK_REASON);
  });

  it("shows the server's reason when GetAK is refused", async () => {
    stubControlPlane({ 'GET /api/v1/capabilities': CAPS_ON, [AK_OP]: refused(404, 'no attestation key') });
    await renderPage();

    await click('Use attestation key');

    const toast = await screen.findByText(/no attestation key/);
    expect(toast.getAttribute('data-testid')).toBe('toast');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(inputOf('AK name (base64)').value).toBe('');
  });
});
