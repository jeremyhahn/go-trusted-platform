import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ok, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import { IAKCertActionsCard } from './iak-cert-actions-card';
import { LDevIDCard } from './ldevid-card';

// #2055: Create LDevID and Activate credential follow the server's
// capabilities: a server that does not offer the operation leaves the control
// disabled with its reason as the title, and a click sends nothing. Delete IAK
// certificate is the status page's control, not the card's.

const LDEVID = 'POST /api/v1/idevid/ldevid';
const ACTIVATE = 'POST /api/v1/idevid/activate-credential';
const OPS = [LDEVID, ACTIVATE];
const REASON = 'not-configured: idevid';

function caps(off: string[] = []): Answer {
  const capabilities = OPS.map((op) =>
    off.includes(op) ? { op, kind: 'route', enabled: false, reason: REASON } : { op, kind: 'route', enabled: true },
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

function type(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

function button(name: string): HTMLButtonElement {
  return screen.getByRole('button', { name }) as HTMLButtonElement;
}

async function expectWithheld(name: string) {
  await waitFor(() => expect(button(name).getAttribute('data-capability-enabled')).toBe('false'));
  expect(button(name).disabled).toBe(true);
  expect(button(name).getAttribute('title')).toBe(REASON);
}

describe('IDevID cards capability gate', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('withholds Create LDevID when the server does not offer it', async () => {
    const sent = stubControlPlane({ 'GET /api/v1/capabilities': caps([LDEVID]) });
    render(withControlPlane(<LDevIDCard />));
    type('Common name', 'device-01.example');

    await expectWithheld('Create LDevID');
    fireEvent.click(button('Create LDevID'));
    expect(sent).not.toContainEqual(expect.objectContaining({ method: 'POST', path: '/api/v1/idevid/ldevid' }));
  });

  it('offers Create LDevID when the server does', async () => {
    stubControlPlane({ 'GET /api/v1/capabilities': caps() });
    render(withControlPlane(<LDevIDCard />));

    await waitFor(() => expect(button('Create LDevID').getAttribute('data-capability-enabled')).toBe('true'));
    type('Common name', 'device-01.example');
    expect(button('Create LDevID').disabled).toBe(false);
  });

  it('withholds Activate credential when the server does not offer it', async () => {
    const sent = stubControlPlane({ 'GET /api/v1/capabilities': caps([ACTIVATE]) });
    render(withControlPlane(<IAKCertActionsCard />));
    type('Credential blob (base64)', 'AAAA');
    type('Secret (base64)', 'AAAA');

    await expectWithheld('Activate credential');
    fireEvent.click(button('Activate credential'));
    expect(sent).not.toContainEqual(
      expect.objectContaining({ method: 'POST', path: '/api/v1/idevid/activate-credential' }),
    );
  });

  it('has no Delete IAK certificate control, the status page owns it', () => {
    stubControlPlane({ 'GET /api/v1/capabilities': caps() });
    render(withControlPlane(<IAKCertActionsCard />));
    expect(screen.queryByRole('button', { name: 'Delete IAK certificate' })).toBeNull();
  });
});
