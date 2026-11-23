import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { IAKCertActionsCard } from './iak-cert-actions-card';

// #2055: the Activate credential card runs ActivateCredential through the
// real SDK client; a refusal reaches the operator verbatim as a destructive
// toast. The control is capability-gated: the server offers it here.

const CAPS = {
  'GET /api/v1/capabilities': ok({
    capabilities: [
      { op: 'POST /api/v1/idevid/ldevid', kind: 'route', enabled: true },
      { op: 'POST /api/v1/idevid/activate-credential', kind: 'route', enabled: true },
    ],
    total: 2,
    enabled: 2,
  }),
};

function renderCard() {
  render(withControlPlane(<IAKCertActionsCard />));
}

// enabledButton waits for the capabilities answer to enable a gated control.
async function enabledButton(name: string): Promise<HTMLButtonElement> {
  const control = (await screen.findByRole('button', { name })) as HTMLButtonElement;
  await waitFor(() => expect(control.getAttribute('data-capability-enabled')).toBe('true'));
  return control;
}

async function click(name: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name }));
  });
}

function type(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

describe('IAKCertActionsCard', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('activates a credential with trimmed inputs and hides the secret', async () => {
    const sent = stubControlPlane({
      ...CAPS,
      'POST /api/v1/idevid/activate-credential': ok({
        status: { success: true, message: 'ok' },
        decryptedSecret: 'c2VjcmV0',
      }),
    });
    renderCard();

    await enabledButton('Activate credential');
    const activate = () => screen.getByRole('button', { name: 'Activate credential' }) as HTMLButtonElement;
    expect(activate().disabled).toBe(true);
    type('Credential blob (base64)', ' YmxvYg== ');
    expect(activate().disabled).toBe(true);
    type('Secret (base64)', ' c2Vj ');
    expect(activate().disabled).toBe(false);
    await click('Activate credential');

    const toast = await screen.findByText('Credential activated: ok');
    expect(toast.getAttribute('data-variant')).toBe('success');
    const posts = sent.filter((r) => r.method === 'POST');
    expect(posts[0]).toMatchObject({ method: 'POST', path: '/api/v1/idevid/activate-credential' });
    expect(posts[0].body).toEqual({ credentialBlob: 'YmxvYg==', secret: 'c2Vj' });
    expect(screen.getByTestId('activate-secret').textContent).toBe('c2VjcmV0');

    await click('Hide');
    expect(screen.queryByTestId('activate-secret')).toBeNull();
  });

  it('shows the activate refusal', async () => {
    stubControlPlane({
      ...CAPS,
      'POST /api/v1/idevid/activate-credential': refused(404, 'IAK not found'),
    });
    renderCard();

    await enabledButton('Activate credential');
    type('Credential blob (base64)', 'YmxvYg==');
    type('Secret (base64)', 'c2Vj');
    await click('Activate credential');

    const toast = await screen.findByText('Activate credential failed: IAK not found');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(screen.queryByTestId('activate-secret')).toBeNull();
  });
});
