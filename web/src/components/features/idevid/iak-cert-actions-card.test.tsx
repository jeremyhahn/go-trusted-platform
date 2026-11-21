import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { IAKCertActionsCard } from './iak-cert-actions-card';

// #2055: the IAK actions card deletes the IAK certificate only after the
// operator confirms, and runs ActivateCredential through the real SDK client;
// a refusal reaches the operator verbatim as a destructive toast.

function renderCard() {
  render(withControlPlane(<IAKCertActionsCard />));
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

  it('asks before deleting and sends nothing on Cancel', async () => {
    const sent = stubControlPlane({});
    renderCard();

    await click('Delete IAK certificate');
    const dialog = await screen.findByRole('dialog');
    expect(dialog.textContent).toContain('Delete the IAK certificate?');
    await click('Cancel');

    expect(sent.some((r) => r.method === 'DELETE')).toBe(false);
  });

  it('deletes the IAK certificate after the confirm', async () => {
    const sent = stubControlPlane({
      'DELETE /api/v1/idevid/iak/certificate': ok({ status: { success: true, message: 'deleted' } }),
    });
    renderCard();

    await click('Delete IAK certificate');
    await screen.findByRole('dialog');
    await click('Confirm');

    const toast = await screen.findByText('IAK certificate deleted: deleted');
    expect(toast.getAttribute('data-variant')).toBe('success');
    const deletes = sent.filter((r) => r.method === 'DELETE');
    expect(deletes).toHaveLength(1);
    expect(deletes[0].path).toBe('/api/v1/idevid/iak/certificate');
  });

  it('shows the delete refusal', async () => {
    stubControlPlane({
      'DELETE /api/v1/idevid/iak/certificate': refused(409, 'TPM2 service not initialized'),
    });
    renderCard();

    await click('Delete IAK certificate');
    await screen.findByRole('dialog');
    await click('Confirm');

    const toast = await screen.findByText('Delete IAK certificate failed: TPM2 service not initialized');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
  });

  it('activates a credential with trimmed inputs and hides the secret', async () => {
    const sent = stubControlPlane({
      'POST /api/v1/idevid/activate-credential': ok({
        status: { success: true, message: 'ok' },
        decryptedSecret: 'c2VjcmV0',
      }),
    });
    renderCard();

    const activate = () => screen.getByRole('button', { name: 'Activate credential' }) as HTMLButtonElement;
    expect(activate().disabled).toBe(true);
    type('Credential blob (base64)', ' YmxvYg== ');
    expect(activate().disabled).toBe(true);
    type('Secret (base64)', ' c2Vj ');
    expect(activate().disabled).toBe(false);
    await click('Activate credential');

    const toast = await screen.findByText('Credential activated: ok');
    expect(toast.getAttribute('data-variant')).toBe('success');
    expect(sent[0]).toMatchObject({ method: 'POST', path: '/api/v1/idevid/activate-credential' });
    expect(sent[0].body).toEqual({ credentialBlob: 'YmxvYg==', secret: 'c2Vj' });
    expect(screen.getByTestId('activate-secret').textContent).toBe('c2VjcmV0');

    await click('Hide');
    expect(screen.queryByTestId('activate-secret')).toBeNull();
  });

  it('shows the activate refusal', async () => {
    stubControlPlane({
      'POST /api/v1/idevid/activate-credential': refused(404, 'IAK not found'),
    });
    renderCard();

    type('Credential blob (base64)', 'YmxvYg==');
    type('Secret (base64)', 'c2Vj');
    await click('Activate credential');

    const toast = await screen.findByText('Activate credential failed: IAK not found');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(screen.queryByTestId('activate-secret')).toBeNull();
  });
});
