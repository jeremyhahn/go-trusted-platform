import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer, type SentRequest } from '@/test/control-plane-fetch';
import { CALifecycleControls } from './ca-lifecycle-controls';

// #2041: the CA overview's InitCA, InstallCACertificates and
// UninstallCACertificates go through the real SDK client (client.ca),
// each gated on its route in GET /api/v1/capabilities.

const INIT = 'POST /api/v1/ca/init';
const INSTALL = 'POST /api/v1/ca/trust/install';
const UNINSTALL = 'POST /api/v1/ca/trust/uninstall';
const LIFECYCLE_OPS = [INIT, INSTALL, UNINSTALL] as const;

// The server's capabilities listing: every lifecycle op enabled except those in off.
function caps(off: string[] = []): Answer {
  const capabilities = LIFECYCLE_OPS.map((op) =>
    off.includes(op)
      ? { op, kind: 'route', enabled: false, reason: 'not-configured: ca' }
      : { op, kind: 'route', enabled: true },
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

function sentTo(sent: SentRequest[], op: string): SentRequest[] {
  return sent.filter((r) => `${r.method} ${r.path}` === op);
}

async function renderEnabled(testid: string) {
  render(withControlPlane(<CALifecycleControls />));
  await waitFor(() => {
    expect(screen.getByTestId(testid).getAttribute('data-capability-enabled')).toBe('true');
  });
}

async function click(el: HTMLElement) {
  await act(async () => {
    fireEvent.click(el);
  });
}

async function toastContaining(text: string, variant: string) {
  await waitFor(() => {
    const toasts = screen.getAllByTestId('toast').filter((t) => t.getAttribute('data-variant') === variant);
    expect(toasts.some((t) => (t.textContent ?? '').includes(text))).toBe(true);
  });
}

describe('CALifecycleControls', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('initializes the CA through POST /api/v1/ca/init and shows the server message', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/capabilities': caps(),
      [INIT]: ok({ status: { success: true, message: 'CA already initialized' } }),
    });
    await renderEnabled('ca-init-control');

    const button = screen.getByTestId('ca-init-control');
    expect(button.textContent).toContain('Initialize CA');
    await click(button);

    await waitFor(() => expect(sentTo(sent, INIT)).toHaveLength(1));
    expect(sentTo(sent, INIT)[0].body).toEqual({ force: false });
    await toastContaining('CA already initialized', 'success');
  });

  it('installs the CA certificates with the intermediates the operator chose', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/capabilities': caps(),
      [INSTALL]: ok({ status: { success: true }, certificatesInstalled: 2, installPath: '/trust/anchors' }),
    });
    await renderEnabled('ca-install-control');

    await click(screen.getByRole('checkbox', { name: 'Include intermediates' }));
    const button = screen.getByTestId('ca-install-control');
    expect(button.textContent).toContain('Install CA certificates');
    await click(button);

    await waitFor(() => expect(sentTo(sent, INSTALL)).toHaveLength(1));
    expect(sentTo(sent, INSTALL)[0].body).toEqual({ includeIntermediates: true });
    await toastContaining('Installed 2 certificate(s) to /trust/anchors', 'success');
  });

  it('uninstalls only after the confirm', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/capabilities': caps(),
      [UNINSTALL]: ok({ status: { success: true }, certificatesRemoved: 0 }),
    });
    await renderEnabled('ca-uninstall-control');

    const button = screen.getByTestId('ca-uninstall-control');
    expect(button.textContent).toContain('Uninstall CA certificates');
    await click(button);
    expect(sentTo(sent, UNINSTALL)).toHaveLength(0);

    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText('Uninstall CA certificates?')).toBeTruthy();
    await click(within(dialog).getByRole('button', { name: 'Uninstall' }));

    await waitFor(() => expect(sentTo(sent, UNINSTALL)).toHaveLength(1));
    expect(sentTo(sent, UNINSTALL)[0].body).toEqual({ includeIntermediates: false });
    await toastContaining('Removed 0 certificate(s)', 'success');
  });

  it.each([
    [INIT, 'ca-init-control'],
    [INSTALL, 'ca-install-control'],
    [UNINSTALL, 'ca-uninstall-control'],
  ])('withholds each control the server does not offer (%s)', async (op, testid) => {
    const sent = stubControlPlane({
      'GET /api/v1/capabilities': caps([op]),
      [op]: ok({ status: { success: true } }),
    });
    render(withControlPlane(<CALifecycleControls />));

    const button = screen.getByTestId(testid) as HTMLButtonElement;
    await waitFor(() => expect(button.title).toBe('not-configured: ca'));
    expect(button.disabled).toBe(true);
    expect(button.getAttribute('data-capability-op')).toBe(op);
    expect(button.getAttribute('data-capability-enabled')).toBe('false');

    await click(button);
    expect(sentTo(sent, op)).toHaveLength(0);
  });

  it('shows a refused write as a destructive toast', async () => {
    stubControlPlane({
      'GET /api/v1/capabilities': caps(),
      [INIT]: refused(403, 'token lacks scope ca:create'),
    });
    await renderEnabled('ca-init-control');

    await click(screen.getByTestId('ca-init-control'));
    await toastContaining('token lacks scope ca:create', 'destructive');
  });
});
