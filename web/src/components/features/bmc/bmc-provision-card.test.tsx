import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer, type SentRequest } from '@/test/control-plane-fetch';
import { BMCProvisionCard } from './bmc-provision-card';

// #2039: the BMC provision card reads ProvisionStatus through useBMCStatus on
// the real SDK client and runs Provision only after a confirm dialog, because
// Provision reboots the host into the installer; refusals reach the operator
// verbatim.

const STATUS_PATH = 'GET /api/v1/bmc/42/provision';
const PROVISION_PATH = 'POST /api/v1/bmc/42/provision';

// The server's op for Provision (pkg/webservice/v1/bmc/routes.go).
const PROVISION_OP = 'POST /api/v1/bmc/{profileID:[0-9]+}/provision';

// The server's capabilities listing: the provision op enabled unless off.
function caps(off: boolean): Answer {
  const capabilities = [
    off
      ? { op: PROVISION_OP, kind: 'route', enabled: false, reason: 'scope bmc:admin required' }
      : { op: PROVISION_OP, kind: 'route', enabled: true },
  ];
  return ok({ capabilities, total: 1, enabled: off ? 0 : 1 });
}

const fixture = {
  provision_id: 'prov-1',
  profile_id: 42,
  status: 'installing',
  started_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:05:00Z',
};

function renderCard(routes: Record<string, Answer>, off = false) {
  const sent = stubControlPlane({
    'GET /api/v1/capabilities': caps(off),
    [STATUS_PATH]: refused(404, 'baremetal: provision not found: 42'),
    ...routes,
  });
  render(withControlPlane(<BMCProvisionCard profileID="42" />));
  return sent;
}

async function statusText(text: string): Promise<HTMLElement> {
  const status = screen.getByTestId('bmc-provision-status');
  await waitFor(() => expect(status.textContent).toContain(text));
  await waitFor(() => expect(provisionButton().getAttribute('data-capability-enabled')).toBe('true'));
  return status;
}

function provisionButton(): HTMLButtonElement {
  return screen.getByRole('button', { name: 'Provision' }) as HTMLButtonElement;
}

async function click(name: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name }));
  });
}

async function confirmProvision() {
  await click('Provision');
  const dialog = await screen.findByRole('dialog');
  await act(async () => {
    fireEvent.click(within(dialog).getByRole('button', { name: 'Confirm provision' }));
  });
}

function posts(sent: SentRequest[]): SentRequest[] {
  return sent.filter((r) => r.method === 'POST');
}

describe('BMCProvisionCard', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('gates Provision on the server provision op', async () => {
    renderCard({});
    await statusText('No provision');
    expect(provisionButton().getAttribute('data-capability-op')).toBe(PROVISION_OP);
    expect(provisionButton().disabled).toBe(false);
  });

  it('disables Provision when the server leaves the op out', async () => {
    const sent = renderCard({ [PROVISION_PATH]: ok({ ...fixture, status: 'pending' }) }, true);
    await waitFor(() => expect(provisionButton().title).toBe('scope bmc:admin required'));
    expect(provisionButton().disabled).toBe(true);
    expect(provisionButton().getAttribute('data-capability-enabled')).toBe('false');
    await click('Provision');
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(posts(sent)).toHaveLength(0);
  });

  it('shows no provision verbatim', async () => {
    renderCard({});

    await statusText('No provision: baremetal: provision not found: 42');
    expect(provisionButton().disabled).toBe(false);
  });

  it('shows a running provision and blocks a second one', async () => {
    renderCard({ [STATUS_PATH]: ok(fixture) });

    const status = await statusText('installing');
    expect(status.textContent).toContain('In progress');
    expect(status.textContent).toContain('prov-1');
    expect(provisionButton().disabled).toBe(true);
  });

  it('allows a new provision after a finished one', async () => {
    renderCard({ [STATUS_PATH]: ok({ ...fixture, status: 'failed', message: 'installer timed out' }) });

    const status = await statusText('Finished');
    expect(status.textContent).toContain('installer timed out');
    expect(provisionButton().disabled).toBe(false);
  });

  it('asks before provisioning and Cancel sends nothing', async () => {
    const sent = renderCard({});
    await statusText('No provision');

    await click('Provision');
    const dialog = await screen.findByRole('dialog');
    expect(dialog.textContent).toContain('Provision this host?');
    expect(dialog.textContent).toContain('BMC profile 42');

    await act(async () => {
      fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    });
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(posts(sent)).toHaveLength(0);
  });

  it('provisions with the ISO URL after Confirm', async () => {
    const sent = renderCard({ [PROVISION_PATH]: ok({ ...fixture, status: 'pending' }) });
    await statusText('No provision');

    fireEvent.change(screen.getByLabelText('ISO URL (optional)'), {
      target: { value: '  https://images.example/installer.iso  ' },
    });
    await confirmProvision();

    await waitFor(() => expect(posts(sent)).toHaveLength(1));
    expect(posts(sent)[0]).toEqual({
      method: 'POST',
      path: '/api/v1/bmc/42/provision',
      body: { iso_url: 'https://images.example/installer.iso' },
    });
    const toast = await screen.findByText('Provision started: prov-1');
    expect(toast.getAttribute('data-variant')).toBe('success');
    await statusText('pending');
  });

  it('provisions without an ISO URL', async () => {
    const sent = renderCard({ [PROVISION_PATH]: ok({ ...fixture, status: 'pending' }) });
    await statusText('No provision');

    await confirmProvision();

    await waitFor(() => expect(posts(sent)).toHaveLength(1));
    expect(posts(sent)[0].body).toEqual({});
  });

  it('shows a refusal verbatim', async () => {
    renderCard({ [PROVISION_PATH]: refused(409, 'baremetal: provision already in progress for profile 42') });
    await statusText('No provision');

    await confirmProvision();

    const toast = await screen.findByText('Provision refused: baremetal: provision already in progress for profile 42');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    await statusText('No provision');
  });

  it('shows a profile without a BMC verbatim', async () => {
    renderCard({ [PROVISION_PATH]: refused(400, 'baremetal: profile 42 has no BMC configuration') });
    await statusText('No provision');

    await confirmProvision();

    const toast = await screen.findByText('Provision refused: baremetal: profile 42 has no BMC configuration');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
  });
});
