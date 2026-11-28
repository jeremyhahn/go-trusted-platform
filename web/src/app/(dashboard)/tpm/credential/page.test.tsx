import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import TPMCredentialPage from './page';

// The credential page drives the real SDK client through the stubbed fetch
// (#2069): MakeCredential shows the blob, the encrypted secret and the
// wrapped secret; ActivateCredential runs only after the confirm dialog;
// GetRandom shows the drawn bytes; "Use platform AK" fills the AK name
// through GetAK; every control is gated on the server's capabilities
// listing; a refusal reaches the operator as a destructive toast carrying
// the server's reason.

const MAKE_PATH = 'POST /api/v1/tpm/make-credential';
const ACTIVATE_PATH = 'POST /api/v1/tpm/activate-credential';
const RANDOM_PATH = 'POST /api/v1/tpm/random';
const AK_PATH = 'GET /api/v1/tpm/ak';
const CAPS_PATH = 'GET /api/v1/capabilities';

const TPM_OPS = [MAKE_PATH, ACTIVATE_PATH, RANDOM_PATH, AK_PATH];

// The server's capabilities listing: every credential op enabled except those in off.
function caps(off: string[] = []): Answer {
  const capabilities = TPM_OPS.map((op) =>
    off.includes(op)
      ? { op, kind: 'route', enabled: false, reason: 'not-configured: tpm' }
      : { op, kind: 'route', enabled: true },
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

const made = ok({ credentialBlob: 'Y2I=', encryptedSecret: 'ZXM=', secret: 'czNjcmV0' });

/**
 * Renders the page and, unless gated is false, waits for the capability gate
 * to read the server's capabilities.
 */
async function renderPage(gated = true) {
  render(withControlPlane(<TPMCredentialPage />));
  if (!gated) return;
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

// waitEnabled waits for the capabilities listing to enable the button.
async function waitEnabled(name: string) {
  await waitFor(() =>
    expect(screen.getByRole('button', { name }).getAttribute('data-capability-enabled')).toBe('true'),
  );
}

async function makeCredential(secret?: string) {
  fireEvent.change(inputOf('AK name (base64)'), { target: { value: 'YWs=' } });
  if (secret !== undefined) {
    fireEvent.change(inputOf('Secret (optional)'), { target: { value: secret } });
  }
  await waitEnabled('Make Credential');
  await click('Make Credential');
}

describe('TPMCredentialPage', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('makes a credential through POST /tpm/make-credential and shows the wrapped secret', async () => {
    const sent = stubControlPlane({ [CAPS_PATH]: caps(), [MAKE_PATH]: made });
    await renderPage();

    await makeCredential('s3cret');

    expect(sent).toContainEqual({
      method: 'POST',
      path: '/api/v1/tpm/make-credential',
      body: { akName: 'YWs=', secret: 'czNjcmV0' },
    });
    await waitFor(() => expect(inputOf('Credential blob (base64)').value).toBe('Y2I='));
    expect(inputOf('Encrypted secret (base64)').value).toBe('ZXM=');
    expect((await screen.findByTestId('wrapped-secret')).textContent).toBe('733363726574');
  });

  it('activates the credential after the confirm dialog', async () => {
    const routes: Record<string, Answer> = {
      [CAPS_PATH]: caps(),
      [MAKE_PATH]: made,
      [ACTIVATE_PATH]: ok({ secret: 'czNjcmV0' }),
    };
    const sent = stubControlPlane(routes);
    await renderPage();

    await makeCredential('s3cret');
    await waitFor(() => expect(inputOf('Credential blob (base64)').value).toBe('Y2I='));
    await waitEnabled('Activate Credential');
    await click('Activate Credential');
    await screen.findByText('Activate this credential?');
    await click('Confirm');

    await waitFor(() =>
      expect(sent).toContainEqual({
        method: 'POST',
        path: '/api/v1/tpm/activate-credential',
        body: { credentialBlob: 'Y2I=', encryptedSecret: 'ZXM=' },
      })
    );
    expect((await screen.findByTestId('activated-secret')).textContent).toBe('733363726574');
  });

  it('sends nothing when the confirm dialog is cancelled', async () => {
    const sent = stubControlPlane({
      [CAPS_PATH]: caps(),
      [MAKE_PATH]: made,
      [ACTIVATE_PATH]: ok({ secret: 'czNjcmV0' }),
    });
    await renderPage();

    await makeCredential('s3cret');
    await waitFor(() => expect(inputOf('Credential blob (base64)').value).toBe('Y2I='));
    await waitEnabled('Activate Credential');
    await click('Activate Credential');
    await screen.findByText('Activate this credential?');
    await click('Cancel');

    await waitFor(() => expect(screen.queryByText('Activate this credential?')).toBeNull());
    expect(sent.some((r) => r.path === '/api/v1/tpm/activate-credential')).toBe(false);
    expect(screen.queryByTestId('activated-secret')).toBeNull();
  });

  it('draws random bytes through POST /tpm/random', async () => {
    const sent = stubControlPlane({ [CAPS_PATH]: caps(), [RANDOM_PATH]: ok({ randomBytes: 'AAEC' }) });
    await renderPage();

    fireEvent.change(inputOf('Number of bytes'), { target: { value: '16' } });
    await waitEnabled('Get Random');
    await click('Get Random');

    expect(sent).toContainEqual({ method: 'POST', path: '/api/v1/tpm/random', body: { numBytes: 16 } });
    expect((await screen.findByTestId('random-bytes')).textContent).toBe('000102');
  });

  it('fills the AK name from the platform AK', async () => {
    const sent = stubControlPlane({
      [CAPS_PATH]: caps(),
      [AK_PATH]: ok({ publicKey: 'cHVi', handle: 2164326402, algorithm: 'KEY_ALGORITHM_ECDSA_P256', name: 'YWtu' }),
    });
    await renderPage();

    await waitEnabled('Use platform AK');
    await click('Use platform AK');

    await waitFor(() => expect(inputOf('AK name (base64)').value).toBe('YWtu'));
    expect(sent.some((r) => r.method === 'GET' && r.path === '/api/v1/tpm/ak')).toBe(true);
  });

  it("shows the server's reason when the platform AK read is refused", async () => {
    stubControlPlane({ [CAPS_PATH]: caps(), [AK_PATH]: refused(403, 'forbidden') });
    await renderPage();

    await waitEnabled('Use platform AK');
    await click('Use platform AK');

    const toast = await screen.findByText('GetAK failed: forbidden');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(inputOf('AK name (base64)').value).toBe('');
  });

  it('withholds the controls the server does not offer', async () => {
    const sent = stubControlPlane({
      [CAPS_PATH]: caps(TPM_OPS),
      [MAKE_PATH]: made,
      [ACTIVATE_PATH]: ok({ secret: 'czNjcmV0' }),
      [RANDOM_PATH]: ok({ randomBytes: 'AAEC' }),
      [AK_PATH]: ok({ name: 'YWtu' }),
    });
    await renderPage(false);

    fireEvent.change(inputOf('AK name (base64)'), { target: { value: 'YWs=' } });
    fireEvent.change(inputOf('Credential blob (base64)'), { target: { value: 'Y2I=' } });
    fireEvent.change(inputOf('Encrypted secret (base64)'), { target: { value: 'ZXM=' } });

    for (const name of ['Make Credential', 'Activate Credential', 'Get Random', 'Use platform AK']) {
      await waitFor(() => {
        const button = screen.getByRole('button', { name }) as HTMLButtonElement;
        expect(button.getAttribute('data-capability-enabled')).toBe('false');
        expect(button.getAttribute('title')).toBe('not-configured: tpm');
        expect(button.disabled).toBe(true);
      });
      await click(name);
    }

    expect(sent.some((r) => r.path.startsWith('/api/v1/tpm/'))).toBe(false);
    expect(screen.queryByText('Activate this credential?')).toBeNull();
  });

  it("shows the server's reason when MakeCredential is refused", async () => {
    stubControlPlane({ [CAPS_PATH]: caps(), [MAKE_PATH]: refused(403, 'forbidden') });
    await renderPage();

    await makeCredential();

    const toast = await screen.findByText('MakeCredential failed: forbidden');
    expect(toast.getAttribute('data-testid')).toBe('toast');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
  });
});
