import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { BMCCertCard } from './bmc-cert-card';

// Placeholder PEM bodies: the card passes them through unchanged.
const CERT_PEM = 'test-cert-pem';
const KEY_PEM = 'test-key-pem';

function renderCard() {
  return render(withControlPlane(<BMCCertCard profileID="42" />));
}

async function click(name: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name }));
  });
}

describe('BMCCertCard', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('enrols with the checked options and shows the pin and steps', async () => {
    const sent = stubControlPlane({
      'POST /api/v1/bmc/42/enroll': ok({
        device_id: '7',
        endpoint: 'bmc-a.example',
        hostname: 'bmc-a.example',
        pin_spki_sha256: 'ab12',
        factory_cert_meta: { subject: 'CN=factory' },
        steps: [
          { name: 'capture', ok: true },
          { name: 'replace', ok: true },
        ],
      }),
    });
    renderCard();
    fireEvent.click(screen.getByRole('checkbox', { name: 'Replace certificate' }));
    fireEvent.click(screen.getByRole('checkbox', { name: 'Publish DANE' }));
    await click('Enroll');

    const toast = await screen.findByText('Enrolled: BMC profile 42');
    expect(toast.getAttribute('data-variant')).toBe('default');
    expect(sent).toEqual([
      {
        method: 'POST',
        path: '/api/v1/bmc/42/enroll',
        body: { replace_certificate: true, dane_publish: true },
      },
    ]);
    expect(screen.getByTestId('bmc-cert-pin').textContent).toContain('ab12');
    expect(screen.getByText(/CN=factory/)).toBeTruthy();
    const steps = screen.getByTestId('bmc-cert-steps').textContent ?? '';
    expect(steps).toContain('capture: ok');
    expect(steps).toContain('replace: ok');
  });

  it('sends an explicit false for an option checked then unchecked', async () => {
    const sent = stubControlPlane({
      'POST /api/v1/bmc/42/enroll': ok({
        device_id: '7',
        endpoint: 'bmc-a.example',
        hostname: 'bmc-a.example',
        pin_spki_sha256: 'ab12',
        steps: [{ name: 'capture', ok: true }],
      }),
    });
    renderCard();
    fireEvent.click(screen.getByRole('checkbox', { name: 'Register DNS' }));
    fireEvent.click(screen.getByRole('checkbox', { name: 'Register DNS' }));
    await click('Enroll');

    await screen.findByText('Enrolled: BMC profile 42');
    expect(sent[0].body).toEqual({ dns_register: false });
  });

  it('reports the failed ceremony steps', async () => {
    const sent = stubControlPlane({
      'POST /api/v1/bmc/42/enroll': ok({
        device_id: '7',
        endpoint: 'bmc-a.example',
        hostname: 'bmc-a.example',
        pin_spki_sha256: 'ab12',
        factory_cert_meta: { subject: 'CN=factory' },
        steps: [
          { name: 'capture', ok: true },
          { name: 'dns', ok: false, detail: 'zone refused' },
        ],
      }),
    });
    renderCard();
    await click('Enroll');

    const toast = await screen.findByText('Enrolment incomplete: failed steps: dns');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(sent[0].body).toEqual({});
    expect(screen.getByTestId('bmc-cert-steps').textContent).toContain('dns: failed (zone refused)');
  });

  it('asks before restoring and sends nothing on Cancel', async () => {
    const sent = stubControlPlane({});
    renderCard();
    await click('Restore factory certificate');

    const dialog = await screen.findByRole('dialog');
    expect(dialog.textContent).toContain('Restore the factory certificate?');
    await click('Cancel');

    expect(sent.filter((r) => r.path === '/api/v1/bmc/42/cert/restore')).toEqual([]);
  });

  it('restores after the confirm', async () => {
    const sent = stubControlPlane({
      'POST /api/v1/bmc/42/cert/restore': ok({
        device_id: '7',
        endpoint: 'bmc-a.example',
        hostname: 'bmc-a.example',
        new_cert_meta: { subject: 'CN=restored' },
        steps: [{ name: 'restore', ok: true }],
      }),
    });
    renderCard();
    await click('Restore factory certificate');
    await screen.findByRole('dialog');
    await click('Confirm');

    const toast = await screen.findByText('Factory certificate restored: BMC profile 42');
    expect(toast.getAttribute('data-variant')).toBe('default');
    expect(sent.filter((r) => r.method === 'POST' && r.path === '/api/v1/bmc/42/cert/restore')).toHaveLength(1);
    expect(screen.getByText(/CN=restored/)).toBeTruthy();
  });

  it('replaces the web certificate and refuses blanks without a request', async () => {
    const sent = stubControlPlane({
      'PUT /api/v1/bmc/42/cert': ok({ status: 'ok' }),
    });
    renderCard();
    await click('Replace web certificate');

    const blank = await screen.findByText('Replace web certificate failed: A certificate PEM is required');
    expect(blank.getAttribute('data-variant')).toBe('destructive');
    expect(sent).toEqual([]);

    fireEvent.change(screen.getByLabelText('Certificate PEM'), { target: { value: CERT_PEM } });
    fireEvent.change(screen.getByLabelText('Private key PEM'), { target: { value: KEY_PEM } });
    await click('Replace web certificate');

    await screen.findByText('Web certificate replaced: BMC profile 42');
    expect(sent).toEqual([
      { method: 'PUT', path: '/api/v1/bmc/42/cert', body: { cert_pem: CERT_PEM, key_pem: KEY_PEM } },
    ]);
    expect((screen.getByLabelText('Certificate PEM') as HTMLTextAreaElement).value).toBe('');
    expect((screen.getByLabelText('Private key PEM') as HTMLTextAreaElement).value).toBe('');
  });

  it('shows the server refusal verbatim', async () => {
    stubControlPlane({
      'POST /api/v1/bmc/42/enroll': refused(404, 'bmc: profile 42 not found'),
    });
    renderCard();
    await click('Enroll');

    const toast = await screen.findByText('Enroll failed: bmc: profile 42 not found');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
  });
});
