import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { type Answer, ok, refused, type SentRequest, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { BMCCertCard } from './bmc-cert-card';

// The webservice's BMC certificate route ops. The capabilities stub offers all
// three, so the tests show the card holds Enroll and Replace back on its own.
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

/** renderCard mounts the card and waits until the capabilities have loaded (no control still "checking"). */
async function renderCard() {
  const view = render(withControlPlane(<BMCCertCard profileID="42" />));
  await waitFor(() =>
    expect(
      screen.getByRole('button', { name: 'Restore factory certificate' }).getAttribute('data-capability-enabled')
    ).toBe('true')
  );
  return view;
}

async function click(name: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name }));
  });
}

/** restoreAnswer is a restore ceremony answer with the given steps. */
function restoreAnswer(steps: { name: string; ok: boolean; detail?: string }[]): Answer {
  return ok({
    device_id: '7',
    endpoint: 'bmc-a.example',
    hostname: 'bmc-a.example',
    new_cert_meta: { subject: 'CN=restored' },
    steps,
  });
}

async function restore() {
  await click('Restore factory certificate');
  await screen.findByRole('dialog');
  await click('Confirm');
}

describe('BMCCertCard', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('offers no Enroll and no Replace control while Restore still works', async () => {
    // The server offers all three routes; the card still holds back enrolment
    // and web certificate replacement until the server updates the trust pin.
    const sent = stub({ 'POST /api/v1/bmc/42/cert/restore': restoreAnswer([{ name: 'restore', ok: true }]) });
    await renderCard();

    expect(screen.queryByRole('button', { name: 'Enroll' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Replace web certificate' })).toBeNull();
    expect(screen.queryByRole('checkbox')).toBeNull();
    expect(screen.queryByLabelText('Certificate PEM')).toBeNull();
    expect(screen.queryByLabelText('Private key PEM')).toBeNull();
    expect(screen.getByTestId('bmc-cert-held-back').textContent).toBe(
      'Enrolment and web certificate replacement are unavailable until the server updates the BMC trust pin.'
    );

    await restore();
    await screen.findByText('Factory certificate restored: BMC profile 42');
    expect(bmc(sent).map((r) => `${r.method} ${r.path}`)).toEqual(['POST /api/v1/bmc/42/cert/restore']);
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
    const sent = stub({ 'POST /api/v1/bmc/42/cert/restore': restoreAnswer([{ name: 'restore', ok: true }]) });
    await renderCard();
    await restore();

    const toast = await screen.findByText('Factory certificate restored: BMC profile 42');
    expect(toast.getAttribute('data-variant')).toBe('default');
    expect(sent.filter((r) => r.method === 'POST' && r.path === '/api/v1/bmc/42/cert/restore')).toHaveLength(1);
    expect(screen.getByText(/CN=restored/)).toBeTruthy();
    expect(screen.getByTestId('bmc-cert-steps').textContent).toContain('restore: ok');
  });

  it('reports the failed ceremony steps', async () => {
    stub({
      'POST /api/v1/bmc/42/cert/restore': restoreAnswer([
        { name: 'restore', ok: true },
        { name: 'dns', ok: false, detail: 'zone refused' },
      ]),
    });
    await renderCard();
    await restore();

    const toast = await screen.findByText('Restore incomplete: failed steps: dns');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(screen.getByTestId('bmc-cert-steps').textContent).toContain('dns: failed (zone refused)');
  });

  it('shows the server refusal verbatim', async () => {
    stub({ 'POST /api/v1/bmc/42/cert/restore': refused(404, 'bmc: profile 42 not found') });
    await renderCard();
    await restore();

    const toast = await screen.findByText('Restore failed: bmc: profile 42 not found');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
  });

  it('gates the restore controls on the restore route', async () => {
    stub({});
    await renderCard();

    const control = screen.getByRole('button', { name: 'Restore factory certificate' });
    expect(control.getAttribute('data-capability-op')).toBe(RESTORE_OP);
    expect(control.getAttribute('data-capability-enabled')).toBe('true');

    await click('Restore factory certificate');
    await screen.findByRole('dialog');
    const confirm = screen.getByRole('button', { name: 'Confirm' });
    expect(confirm.getAttribute('data-capability-op')).toBe(RESTORE_OP);
    expect(confirm.getAttribute('data-capability-enabled')).toBe('true');
  });

  it('disables the restore control when the server does not offer its route, with the reason', async () => {
    const reason = 'not-configured: bmc ceremony';
    const sent = stub({}, { [RESTORE_OP]: reason });
    render(withControlPlane(<BMCCertCard profileID="42" />));

    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Restore factory certificate' }).getAttribute('title')).toBe(reason)
    );
    const control = screen.getByRole('button', { name: 'Restore factory certificate' }) as HTMLButtonElement;
    expect(control.disabled).toBe(true);
    expect(control.getAttribute('data-capability-enabled')).toBe('false');

    await click('Restore factory certificate');
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(bmc(sent)).toEqual([]);
  });
});
