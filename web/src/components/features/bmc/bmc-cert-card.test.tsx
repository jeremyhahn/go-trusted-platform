import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { type Answer, ok, refused, type SentRequest, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { BMCCertCard } from './bmc-cert-card';

// The webservice's route ops for the certificate card's write controls.
const ENROLL_OP = 'POST /api/v1/bmc/{profileID:[0-9]+}/enroll';
const RESTORE_OP = 'POST /api/v1/bmc/{profileID:[0-9]+}/cert/restore';
const REPLACE_OP = 'PUT /api/v1/bmc/{profileID:[0-9]+}/cert';

/** caps answers the capabilities listing: every op enabled unless it is a key of off (value = reason). */
function caps(off: Record<string, string> = {}): Answer {
  const capabilities = [ENROLL_OP, RESTORE_OP, REPLACE_OP].map((op) =>
    op in off ? { op, kind: 'route', enabled: false, reason: off[op] } : { op, kind: 'route', enabled: true }
  );
  return ok({
    capabilities,
    total: capabilities.length,
    enabled: capabilities.filter((c) => c.enabled).length,
  });
}

function stub(routes: Record<string, Answer>, off: Record<string, string> = {}): SentRequest[] {
  return stubControlPlane({ 'GET /api/v1/capabilities': caps(off), ...routes });
}

/** bmc drops the capabilities fetch, leaving the card's own requests. */
function bmc(sent: SentRequest[]): SentRequest[] {
  return sent.filter((r) => r.path !== '/api/v1/capabilities');
}

// Placeholder PEM bodies: the card passes them through unchanged.
const CERT_PEM = 'test-cert-pem';
const KEY_PEM = 'test-key-pem';

// A replace never updates the stored pin, so the success toast says to enrol again.
const REPLACED_TOAST = 'Web certificate replaced: BMC profile 42; enroll again to refresh the stored pin';

/** renderCard mounts the card and waits until the capabilities have loaded (no control still "checking"). */
async function renderCard() {
  const view = render(withControlPlane(<BMCCertCard profileID="42" />));
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Enroll' }).getAttribute('data-capability-enabled')).not.toBe('false')
  );
  return view;
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
    const sent = stub({
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
    await renderCard();
    await click('Enroll');

    const toast = await screen.findByText('Enrolled: BMC profile 42');
    expect(toast.getAttribute('data-variant')).toBe('default');
    expect(bmc(sent)).toEqual([
      {
        method: 'POST',
        path: '/api/v1/bmc/42/enroll',
        body: { replace_certificate: false, rotate_password: false, dns_register: true, dane_publish: false },
      },
    ]);
    expect(screen.getByTestId('bmc-cert-pin').textContent).toContain('ab12');
    expect(screen.getByText(/CN=factory/)).toBeTruthy();
    const steps = screen.getByTestId('bmc-cert-steps').textContent ?? '';
    expect(steps).toContain('capture: ok');
    expect(steps).toContain('replace: ok');
  });

  it('shows the server enroll defaults checked and offers no option the server does not perform', async () => {
    stub({});
    await renderCard();

    expect(screen.getByRole('checkbox', { name: 'Register DNS' }).getAttribute('aria-checked')).toBe('true');
    // DANE is published only when the certificate is replaced, which the
    // server does not do yet, so the card offers no DANE option.
    expect(screen.queryByRole('checkbox', { name: 'Publish DANE' })).toBeNull();
    expect(screen.queryByRole('checkbox', { name: 'Rotate password' })).toBeNull();
    expect(screen.queryByRole('checkbox', { name: 'Replace certificate' })).toBeNull();
  });

  it('sends an explicit false for an unchecked default', async () => {
    const sent = stub({
      'POST /api/v1/bmc/42/enroll': ok({
        device_id: '7',
        endpoint: 'bmc-a.example',
        hostname: 'bmc-a.example',
        pin_spki_sha256: 'ab12',
        steps: [{ name: 'capture', ok: true }],
      }),
    });
    await renderCard();
    fireEvent.click(screen.getByRole('checkbox', { name: 'Register DNS' }));
    await click('Enroll');

    await screen.findByText('Enrolled: BMC profile 42');
    expect(bmc(sent)[0].body).toEqual({
      replace_certificate: false,
      rotate_password: false,
      dns_register: false,
      dane_publish: false,
    });
  });

  it('reports the failed ceremony steps', async () => {
    const sent = stub({
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
    await renderCard();
    await click('Enroll');

    const toast = await screen.findByText('Enrolment incomplete: failed steps: dns');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    // Untouched, every option goes explicitly, with the server defaults.
    expect(bmc(sent)[0].body).toEqual({
      replace_certificate: false,
      rotate_password: false,
      dns_register: true,
      dane_publish: false,
    });
    expect(screen.getByTestId('bmc-cert-steps').textContent).toContain('dns: failed (zone refused)');
  });

  it('asks before restoring and sends nothing on Cancel', async () => {
    const sent = stub({});
    await renderCard();
    await click('Restore factory certificate');

    const dialog = await screen.findByRole('dialog');
    expect(dialog.textContent).toContain('Restore the factory certificate?');
    await click('Cancel');

    expect(sent.filter((r) => r.path === '/api/v1/bmc/42/cert/restore')).toEqual([]);
  });

  it('restores after the confirm', async () => {
    const sent = stub({
      'POST /api/v1/bmc/42/cert/restore': ok({
        device_id: '7',
        endpoint: 'bmc-a.example',
        hostname: 'bmc-a.example',
        new_cert_meta: { subject: 'CN=restored' },
        steps: [{ name: 'restore', ok: true }],
      }),
    });
    await renderCard();
    await click('Restore factory certificate');
    await screen.findByRole('dialog');
    await click('Confirm');

    const toast = await screen.findByText('Factory certificate restored: BMC profile 42');
    expect(toast.getAttribute('data-variant')).toBe('default');
    expect(sent.filter((r) => r.method === 'POST' && r.path === '/api/v1/bmc/42/cert/restore')).toHaveLength(1);
    expect(screen.getByText(/CN=restored/)).toBeTruthy();
  });

  it('replaces the web certificate and refuses blanks without a request', async () => {
    const sent = stub({
      'PUT /api/v1/bmc/42/cert': ok({ status: 'ok' }),
    });
    await renderCard();
    await click('Replace web certificate');

    const blank = await screen.findByText('Replace web certificate failed: A certificate PEM is required');
    expect(blank.getAttribute('data-variant')).toBe('destructive');
    expect(bmc(sent)).toEqual([]);

    fireEvent.change(screen.getByLabelText('Certificate PEM'), { target: { value: CERT_PEM } });
    fireEvent.change(screen.getByLabelText('Private key PEM'), { target: { value: KEY_PEM } });
    await click('Replace web certificate');

    await screen.findByText(REPLACED_TOAST);
    expect(bmc(sent)).toEqual([
      { method: 'PUT', path: '/api/v1/bmc/42/cert', body: { cert_pem: CERT_PEM, key_pem: KEY_PEM } },
    ]);
    expect((screen.getByLabelText('Certificate PEM') as HTMLTextAreaElement).value).toBe('');
    expect((screen.getByLabelText('Private key PEM') as HTMLTextAreaElement).value).toBe('');
  });

  it('fails an enrolment whose answer carries no SPKI pin', async () => {
    stub({
      'POST /api/v1/bmc/42/enroll': ok({
        device_id: '7',
        endpoint: 'bmc-a.example',
        hostname: 'bmc-a.example',
        pin_spki_sha256: '',
        steps: [{ name: 'capture', ok: true }],
      }),
    });
    await renderCard();
    await click('Enroll');

    const toast = await screen.findByText(/^Enroll failed/);
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(screen.queryByText(/^Enrolled/)).toBeNull();
    expect(screen.queryByTestId('bmc-cert-pin')).toBeNull();
  });

  it('drops the shown pin after a web certificate replace', async () => {
    stub({
      'POST /api/v1/bmc/42/enroll': ok({
        device_id: '7',
        endpoint: 'bmc-a.example',
        hostname: 'bmc-a.example',
        pin_spki_sha256: 'ab12',
        steps: [{ name: 'capture', ok: true }],
      }),
      'PUT /api/v1/bmc/42/cert': ok({ status: 'ok' }),
    });
    await renderCard();
    await click('Enroll');
    await screen.findByText('Enrolled: BMC profile 42');
    expect(screen.getByTestId('bmc-cert-pin').textContent).toContain('ab12');

    fireEvent.change(screen.getByLabelText('Certificate PEM'), { target: { value: CERT_PEM } });
    fireEvent.change(screen.getByLabelText('Private key PEM'), { target: { value: KEY_PEM } });
    await click('Replace web certificate');

    await screen.findByText(REPLACED_TOAST);
    expect(screen.queryByTestId('bmc-cert-pin')).toBeNull();
  });

  it('shows the server refusal verbatim', async () => {
    stub({
      'POST /api/v1/bmc/42/enroll': refused(404, 'bmc: profile 42 not found'),
    });
    await renderCard();
    await click('Enroll');

    const toast = await screen.findByText('Enroll failed: bmc: profile 42 not found');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
  });

  it('gates every certificate control on its route', async () => {
    stub({});
    await renderCard();

    const enroll = screen.getByRole('button', { name: 'Enroll' });
    const restore = screen.getByRole('button', { name: 'Restore factory certificate' });
    const replace = screen.getByRole('button', { name: 'Replace web certificate' });
    expect(enroll.getAttribute('data-capability-op')).toBe(ENROLL_OP);
    expect(restore.getAttribute('data-capability-op')).toBe(RESTORE_OP);
    expect(replace.getAttribute('data-capability-op')).toBe(REPLACE_OP);
    for (const control of [enroll, restore, replace]) {
      expect(control.getAttribute('data-capability-enabled')).toBe('true');
    }

    await click('Restore factory certificate');
    await screen.findByRole('dialog');
    const confirm = screen.getByRole('button', { name: 'Confirm' });
    expect(confirm.getAttribute('data-capability-op')).toBe(RESTORE_OP);
    expect(confirm.getAttribute('data-capability-enabled')).toBe('true');
  });

  it('disables the controls whose route the server does not offer, with the reason', async () => {
    const reason = 'not-configured: bmc ceremony';
    const sent = stub({}, { [RESTORE_OP]: reason, [REPLACE_OP]: reason });
    render(withControlPlane(<BMCCertCard profileID="42" />));

    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Restore factory certificate' }).getAttribute('title')).toBe(reason)
    );
    const restore = screen.getByRole('button', { name: 'Restore factory certificate' }) as HTMLButtonElement;
    const replace = screen.getByRole('button', { name: 'Replace web certificate' }) as HTMLButtonElement;
    for (const control of [restore, replace]) {
      expect(control.disabled).toBe(true);
      expect(control.getAttribute('data-capability-enabled')).toBe('false');
      expect(control.getAttribute('title')).toBe(reason);
    }
    const enroll = screen.getByRole('button', { name: 'Enroll' }) as HTMLButtonElement;
    expect(enroll.getAttribute('data-capability-enabled')).toBe('true');
    expect(enroll.disabled).toBe(false);

    await click('Restore factory certificate');
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(bmc(sent)).toEqual([]);
  });
});
