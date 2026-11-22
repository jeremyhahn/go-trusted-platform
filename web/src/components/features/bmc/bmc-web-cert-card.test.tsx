import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import { BMCWebCertCard, certExpiryText } from './bmc-web-cert-card';

// #2039: the BMC web certificate card reads GetWebCertificate through
// useBMCStatus on the real SDK client, words the days remaining and warns
// under 30 days; a refusal reaches the operator verbatim.

const CERT_PATH = 'GET /api/v1/bmc/42/cert';

function cert(daysRemaining: number): Answer {
  return ok({
    subject: 'CN=bmc.example',
    issuer: 'CN=Example CA',
    serial_number: '0A1B2C',
    not_before: '2026-01-01T00:00:00Z',
    not_after: '2027-01-01T00:00:00Z',
    days_remaining: daysRemaining,
  });
}

async function renderCard(answer: Answer) {
  stubControlPlane({ [CERT_PATH]: answer });
  render(withControlPlane(<BMCWebCertCard profileID="42" />));
}

async function expiryText(): Promise<string> {
  const expiry = await screen.findByTestId('bmc-cert-expiry');
  return expiry.textContent ?? '';
}

describe('BMCWebCertCard', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('shows the certificate on mount', async () => {
    await renderCard(cert(90));

    await waitFor(() => {
      const list = within(screen.getByTestId('bmc-web-cert'));
      expect(list.getByText('CN=bmc.example')).toBeDefined();
      expect(list.getByText('CN=Example CA')).toBeDefined();
      expect(list.getByText('0A1B2C')).toBeDefined();
      expect(list.getByText('2027-01-01T00:00:00Z')).toBeDefined();
    });
    expect(await expiryText()).toBe('Expires in 90 days');
    expect(screen.queryByTestId('bmc-cert-warning')).toBeNull();
  });

  it('warns under 30 days', async () => {
    await renderCard(cert(12));

    const warning = await screen.findByTestId('bmc-cert-warning');
    expect(warning.textContent).toContain('expires in fewer than 30 days');
    expect(await expiryText()).toBe('Expires in 12 days');
  });

  it('does not warn at 30 days', async () => {
    await renderCard(cert(30));

    expect(await expiryText()).toBe('Expires in 30 days');
    expect(screen.queryByTestId('bmc-cert-warning')).toBeNull();
  });

  it('says an expired certificate expired', async () => {
    await renderCard(cert(-3));

    const warning = await screen.findByTestId('bmc-cert-warning');
    expect(warning.textContent).toContain('has expired');
    expect(await expiryText()).toBe('Expired 3 days ago');
  });

  it('shows an unknown profile verbatim', async () => {
    await renderCard(refused(404, 'bmc: profile not found: 42'));

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('Web certificate unavailable: bmc: profile not found: 42');
    expect(screen.queryByTestId('bmc-web-cert')).toBeNull();
  });

  it('words the expiry', () => {
    expect(certExpiryText(0)).toBe('Expires today');
    expect(certExpiryText(1)).toBe('Expires in 1 day');
    expect(certExpiryText(45)).toBe('Expires in 45 days');
    expect(certExpiryText(-1)).toBe('Expired 1 day ago');
  });
});
