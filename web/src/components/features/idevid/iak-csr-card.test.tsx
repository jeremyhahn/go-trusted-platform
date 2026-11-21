import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { pemToBase64 } from '@/hooks/use-idevid-certs';
import { IAKCSRCard } from './iak-csr-card';

// #2055: the IAK CSR card drives CreateIAKCSR, InstallIDevIDCertificate and
// InstallIAKCertificate through the real SDK client; a refusal reaches the
// operator verbatim as a destructive toast.

const PEM = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----';

function renderCard() {
  render(withControlPlane(<IAKCSRCard />));
}

async function click(name: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name }));
  });
}

function type(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

function button(name: string): HTMLButtonElement {
  return screen.getByRole('button', { name }) as HTMLButtonElement;
}

describe('IAKCSRCard', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('creates an IAK CSR with a trimmed common name and shows the PEM', async () => {
    const sent = stubControlPlane({
      'POST /api/v1/idevid/iak/csr': ok({
        status: { success: true, message: 'ok' },
        csrPem: pemToBase64('-----BEGIN CERTIFICATE REQUEST-----\nMIIC\n-----END CERTIFICATE REQUEST-----'),
      }),
    });
    renderCard();

    type('Common name', ' device-1.example.test ');
    await click('Create IAK CSR');

    const toast = await screen.findByText('IAK CSR created: ok');
    expect(toast.getAttribute('data-variant')).toBe('success');
    expect(sent[0]).toMatchObject({ method: 'POST', path: '/api/v1/idevid/iak/csr' });
    expect(sent[0].body).toEqual({ template: { commonName: 'device-1.example.test' } });
    expect(screen.getByTestId('iak-csr-pem').textContent).toContain('BEGIN CERTIFICATE REQUEST');
  });

  it('sends an empty body without a common name', async () => {
    const sent = stubControlPlane({
      'POST /api/v1/idevid/iak/csr': ok({
        status: { success: true, message: 'created' },
        csrPem: pemToBase64('-----BEGIN CERTIFICATE REQUEST-----\nMIIC\n-----END CERTIFICATE REQUEST-----'),
      }),
    });
    renderCard();

    await click('Create IAK CSR');

    await screen.findByText('IAK CSR created: created');
    expect(sent[0].body).toEqual({});
  });

  it('shows the CSR refusal', async () => {
    stubControlPlane({
      'POST /api/v1/idevid/iak/csr': refused(409, 'TPM2 service not initialized'),
    });
    renderCard();

    await click('Create IAK CSR');

    const toast = await screen.findByText('Create IAK CSR failed: TPM2 service not initialized');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(screen.queryByTestId('iak-csr-pem')).toBeNull();
  });

  it('keeps the install buttons disabled until the text is a PEM block', () => {
    stubControlPlane({});
    renderCard();

    expect(button('Install IDevID certificate').disabled).toBe(true);
    expect(button('Install IAK certificate').disabled).toBe(true);

    type('Certificate PEM', 'not a pem');
    expect(button('Install IDevID certificate').disabled).toBe(true);
    expect(button('Install IAK certificate').disabled).toBe(true);
    expect(screen.getByTestId('pem-hint')).toBeDefined();

    type('Certificate PEM', PEM);
    expect(button('Install IDevID certificate').disabled).toBe(false);
    expect(button('Install IAK certificate').disabled).toBe(false);
    expect(screen.queryByTestId('pem-hint')).toBeNull();
  });

  it('installs the IDevID certificate as base64 PEM', async () => {
    const sent = stubControlPlane({
      'POST /api/v1/idevid/certificate': ok({ status: { success: true, message: 'installed' } }),
    });
    renderCard();

    type('Certificate PEM', PEM);
    await click('Install IDevID certificate');

    const toast = await screen.findByText('IDevID certificate installed: installed');
    expect(toast.getAttribute('data-variant')).toBe('success');
    expect(sent[0]).toMatchObject({ method: 'POST', path: '/api/v1/idevid/certificate' });
    expect(sent[0].body).toEqual({ certificatePem: pemToBase64(PEM) });
    expect((screen.getByLabelText('Certificate PEM') as HTMLTextAreaElement).value).toBe('');
  });

  it('shows the IAK certificate refusal and keeps the text', async () => {
    stubControlPlane({
      'POST /api/v1/idevid/iak/certificate': refused(400, 'certificate does not match the IAK'),
    });
    renderCard();

    type('Certificate PEM', PEM);
    await click('Install IAK certificate');

    const toast = await screen.findByText('Install IAK certificate failed: certificate does not match the IAK');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect((screen.getByLabelText('Certificate PEM') as HTMLTextAreaElement).value).toBe(PEM);
  });
});
