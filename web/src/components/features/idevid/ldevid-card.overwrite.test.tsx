import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ok, refused, stubControlPlane, withControlPlane, type SentRequest } from '@/test/control-plane-fetch';
import { LDevIDCard } from './ldevid-card';

// #2055: the LDevID card replaces an existing key only after a confirm and
// hints at overwrite when the handle is taken.

const ROUTE = 'POST /api/v1/idevid/ldevid';
const CN = 'ldevid-1.example.test';

// Create LDevID is capability-gated (#2055): the server offers it here.
const CAPS = {
  'GET /api/v1/capabilities': ok({
    capabilities: [{ op: 'POST /api/v1/idevid/ldevid', kind: 'route', enabled: true }],
    total: 1,
    enabled: 1,
  }),
};

const issued = ok({
  status: { success: true, message: 'issued' },
  csrPem: btoa('-----BEGIN CERTIFICATE REQUEST-----\nMIIC\n-----END CERTIFICATE REQUEST-----'),
  certificatePem: btoa('-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----'),
  certificate: { serialNumber: '0a' },
});

function typeCommonName() {
  fireEvent.change(screen.getByLabelText('Common name'), { target: { value: CN } });
}

function checkOverwrite() {
  fireEvent.click(screen.getByRole('checkbox', { name: 'Overwrite the existing key' }));
}

// click waits for a gated control's capabilities answer before clicking it.
async function click(name: string) {
  const control = screen.getByRole('button', { name });
  if (control.hasAttribute('data-capability-op')) {
    await waitFor(() => expect(control.getAttribute('data-capability-enabled')).toBe('true'));
  }
  await act(async () => {
    fireEvent.click(control);
  });
}

function posts(sent: SentRequest[]) {
  return sent.filter((r) => r.method === 'POST');
}

describe('LDevIDCard overwrite', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('sends no overwrite field while the box is unchecked', async () => {
    const sent = stubControlPlane({ ...CAPS, [ROUTE]: issued });
    render(withControlPlane(<LDevIDCard />));
    // The box exists and is unchecked.
    expect(screen.getByRole('checkbox', { name: 'Overwrite the existing key' }).getAttribute('aria-checked')).toBe('false');
    typeCommonName();
    await click('Create LDevID');

    await screen.findByText('LDevID created: issued');
    expect(screen.queryByRole('dialog')).toBeNull();
    const p = posts(sent);
    expect(p).toHaveLength(1);
    expect(p[0].body as Record<string, unknown>).not.toHaveProperty('overwrite');
  });

  it('asks before an overwrite and sends nothing on Cancel', async () => {
    const sent = stubControlPlane({ ...CAPS, [ROUTE]: issued });
    render(withControlPlane(<LDevIDCard />));
    typeCommonName();
    checkOverwrite();
    await click('Create LDevID');

    const dialog = await screen.findByRole('dialog');
    expect(dialog.textContent).toContain('Replace the LDevID key?');
    expect(dialog.textContent).toContain('handle 0x81010102');
    await click('Cancel');
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(posts(sent)).toHaveLength(0);
  });

  it('overwrites after the confirm', async () => {
    const sent = stubControlPlane({ ...CAPS, [ROUTE]: issued });
    render(withControlPlane(<LDevIDCard />));
    typeCommonName();
    checkOverwrite();
    await click('Create LDevID');
    await screen.findByRole('dialog');
    await click('Confirm');

    const toast = await screen.findByText('LDevID created: issued');
    expect(toast.getAttribute('data-variant')).toBe('success');
    const p = posts(sent);
    expect(p).toHaveLength(1);
    expect(p[0].body).toMatchObject({ overwrite: true });
  });

  it('shows the taken-handle refusal and the overwrite hint', async () => {
    stubControlPlane({ ...CAPS, [ROUTE]: refused(409, 'LDevID key already exists at handle') });
    render(withControlPlane(<LDevIDCard />));
    typeCommonName();
    await click('Create LDevID');

    const toast = await screen.findByText('Create LDevID failed: LDevID key already exists at handle');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(screen.getByTestId('ldevid-overwrite-hint').textContent).toBe(
      'A key exists at the handle. Check Overwrite the existing key to replace it.'
    );
  });

  it('shows no hint for other refusals', async () => {
    stubControlPlane({ ...CAPS, [ROUTE]: refused(409, 'TPM2 service not initialized') });
    render(withControlPlane(<LDevIDCard />));
    typeCommonName();
    await click('Create LDevID');

    await screen.findByText('Create LDevID failed: TPM2 service not initialized');
    expect(screen.queryByTestId('ldevid-overwrite-hint')).toBeNull();
  });
});
