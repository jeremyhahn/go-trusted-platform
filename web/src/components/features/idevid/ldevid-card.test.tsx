import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { LDevIDCard } from './ldevid-card';

// #2055: the LDevID card drives CreateLDevID (POST /api/v1/idevid/ldevid)
// through the real SDK client; fetch is the stub.

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

function type(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
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

describe('LDevIDCard', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('keeps Create disabled until a common name is typed', async () => {
    stubControlPlane(CAPS);
    render(withControlPlane(<LDevIDCard />));
    const create = screen.getByRole('button', { name: 'Create LDevID' }) as HTMLButtonElement;
    await waitFor(() => expect(create.getAttribute('data-capability-enabled')).toBe('true'));
    expect(create.disabled).toBe(true);
    type('Common name', '  ');
    expect(create.disabled).toBe(true);
    type('Common name', CN);
    expect(create.disabled).toBe(false);

    const select = screen.getByLabelText('Algorithm') as HTMLSelectElement;
    expect(Array.from(select.options).map((o) => o.textContent)).toEqual([
      'ECDSA P-256',
      'ECDSA P-384',
      'RSA 2048',
      'RSA 3072',
    ]);
    expect(select.value).toBe('ECDSA_P256');
    expect(screen.getByText('Handle 0x81010102')).toBeTruthy();
  });

  it('creates an LDevID with the defaults', async () => {
    const sent = stubControlPlane({ ...CAPS, [ROUTE]: issued });
    render(withControlPlane(<LDevIDCard />));
    type('Common name', ` ${CN} `);
    await click('Create LDevID');

    const toast = await screen.findByText('LDevID created: issued');
    expect(toast.getAttribute('data-variant')).toBe('success');
    const posts = sent.filter((r) => r.method === 'POST');
    expect(posts).toHaveLength(1);
    expect(posts[0].body).toEqual({
      template: { commonName: CN },
      algorithm: 'DEVICE_KEY_ALGORITHM_ECDSA_P256',
      handle: 0x81010102,
    });
  });

  it('sends the organization, algorithm and validity', async () => {
    const sent = stubControlPlane({ ...CAPS, [ROUTE]: issued });
    render(withControlPlane(<LDevIDCard />));
    type('Common name', CN);
    type('Organization', 'Example Org');
    type('Algorithm', 'RSA_3072');
    type('Validity (days)', '30');
    await click('Create LDevID');

    await screen.findByText('LDevID created: issued');
    const posts = sent.filter((r) => r.method === 'POST');
    expect(posts).toHaveLength(1);
    expect(posts[0].body).toEqual({
      template: { commonName: CN, organization: 'Example Org' },
      algorithm: 'DEVICE_KEY_ALGORITHM_RSA_3072',
      handle: 0x81010102,
      validityDays: 30,
    });
  });

  it('shows the CSR and certificate PEM', async () => {
    stubControlPlane({ ...CAPS, [ROUTE]: issued });
    render(withControlPlane(<LDevIDCard />));
    type('Common name', CN);
    await click('Create LDevID');

    await screen.findByText('LDevID created: issued');
    expect(screen.getByTestId('ldevid-csr-pem').textContent).toContain('BEGIN CERTIFICATE REQUEST');
    expect(screen.getByTestId('ldevid-cert-pem').textContent).toContain('BEGIN CERTIFICATE-----');
  });

  it('shows the no-IDevID refusal', async () => {
    const msg = 'idevid: LDevID refused, device has no proven IDevID: no IDevID certificate installed';
    stubControlPlane({ ...CAPS, [ROUTE]: refused(409, msg) });
    render(withControlPlane(<LDevIDCard />));
    type('Common name', CN);
    await click('Create LDevID');

    const toast = await screen.findByText(`Create LDevID failed: ${msg}`);
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(screen.queryByTestId('ldevid-cert-pem')).toBeNull();
  });

  it('shows the bad request refusal', async () => {
    stubControlPlane({ ...CAPS, [ROUTE]: refused(400, 'common name is required') });
    render(withControlPlane(<LDevIDCard />));
    type('Common name', CN);
    await click('Create LDevID');

    const toast = await screen.findByText('Create LDevID failed: common name is required');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
  });
});
