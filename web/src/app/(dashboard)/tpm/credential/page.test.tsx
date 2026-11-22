import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import TPMCredentialPage from './page';

// The credential page drives the real SDK client through the stubbed fetch
// (#2069): MakeCredential shows the blob, the encrypted secret and the
// wrapped secret; ActivateCredential runs only after the confirm dialog;
// GetRandom shows the drawn bytes; a refusal reaches the operator as a
// destructive toast carrying the server's reason.

const MAKE_PATH = 'POST /api/v1/tpm/make-credential';
const ACTIVATE_PATH = 'POST /api/v1/tpm/activate-credential';
const RANDOM_PATH = 'POST /api/v1/tpm/random';

const CAPS_ON = ok({ capabilities: ['POST /api/v1/tpm/pcrs/extend', 'POST /api/v1/tpm/make-credential', 'POST /api/v1/tpm/activate-credential', 'POST /api/v1/tpm/random'].map((op) => ({ op, kind: 'route', enabled: true })) });

const made = ok({ credentialBlob: 'Y2I=', encryptedSecret: 'ZXM=', secret: 'czNjcmV0' });

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

async function makeCredential(secret?: string) {
  fireEvent.change(inputOf('AK name (base64)'), { target: { value: 'YWs=' } });
  if (secret !== undefined) {
    fireEvent.change(inputOf('Secret (optional)'), { target: { value: secret } });
  }
  await click('Make Credential');
}

describe('TPMCredentialPage', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('makes a credential through POST /tpm/make-credential and shows the wrapped secret', async () => {
    const sent = stubControlPlane({ [MAKE_PATH]: made, 'GET /api/v1/capabilities': CAPS_ON });
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
      [MAKE_PATH]: made,
      [ACTIVATE_PATH]: ok({ secret: 'czNjcmV0' }),
    'GET /api/v1/capabilities': CAPS_ON,
    };
    const sent = stubControlPlane(routes);
    await renderPage();

    await makeCredential('s3cret');
    await waitFor(() => expect(inputOf('Credential blob (base64)').value).toBe('Y2I='));
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
      [MAKE_PATH]: made,
      [ACTIVATE_PATH]: ok({ secret: 'czNjcmV0' }),
    'GET /api/v1/capabilities': CAPS_ON,
    });
    await renderPage();

    await makeCredential('s3cret');
    await waitFor(() => expect(inputOf('Credential blob (base64)').value).toBe('Y2I='));
    await click('Activate Credential');
    await screen.findByText('Activate this credential?');
    await click('Cancel');

    await waitFor(() => expect(screen.queryByText('Activate this credential?')).toBeNull());
    expect(sent.some((r) => r.path === '/api/v1/tpm/activate-credential')).toBe(false);
    expect(screen.queryByTestId('activated-secret')).toBeNull();
  });

  it('draws random bytes through POST /tpm/random', async () => {
    const sent = stubControlPlane({ [RANDOM_PATH]: ok({ randomBytes: 'AAEC' }), 'GET /api/v1/capabilities': CAPS_ON });
    await renderPage();

    fireEvent.change(inputOf('Number of bytes'), { target: { value: '16' } });
    await click('Get Random');

    expect(sent).toContainEqual({ method: 'POST', path: '/api/v1/tpm/random', body: { numBytes: 16 } });
    expect((await screen.findByTestId('random-bytes')).textContent).toBe('000102');
  });

  it("shows the server's reason when MakeCredential is refused", async () => {
    stubControlPlane({ [MAKE_PATH]: refused(403, 'forbidden'), 'GET /api/v1/capabilities': CAPS_ON });
    await renderPage();

    await makeCredential();

    const toast = await screen.findByText('MakeCredential failed: forbidden');
    expect(toast.getAttribute('data-testid')).toBe('toast');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
  });
});
