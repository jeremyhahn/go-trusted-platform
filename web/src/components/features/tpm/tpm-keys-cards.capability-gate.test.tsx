import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import { TPMCertifyCard } from './tpm-certify-card';
import { TPMKeyLifecycleCard } from './tpm-key-lifecycle-card';

// The TPM key cards follow the server's capabilities (#2068): Create/Evict EK,
// Create/Evict SRK, Import certificate, Certify and Evict AK are each wrapped
// in the capability gate, so a server that does not offer the operation leaves
// the control disabled with the server's reason as its title.

const LIFECYCLE_OPS = [
  'POST /api/v1/tpm/ek',
  'DELETE /api/v1/tpm/ek',
  'POST /api/v1/tpm/srk',
  'DELETE /api/v1/tpm/srk',
  'POST /api/v1/tpm/ek/certificate',
];

const CERTIFY_OPS = ['POST /api/v1/tpm/certify', 'DELETE /api/v1/tpm/ak'];

const TPM_OPS = [...LIFECYCLE_OPS, ...CERTIFY_OPS];

const REASON = 'not-configured: tpm';

function caps(off: string[] = []): Answer {
  const capabilities = TPM_OPS.map((op) =>
    off.includes(op) ? { op, kind: 'route', enabled: false, reason: REASON } : { op, kind: 'route', enabled: true },
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

function button(name: string): HTMLButtonElement {
  return screen.getByRole('button', { name }) as HTMLButtonElement;
}

async function expectWithheld(name: string) {
  await waitFor(() => expect(button(name).getAttribute('title')).toBe(REASON));
  expect(button(name).disabled).toBe(true);
  expect(button(name).getAttribute('data-capability-enabled')).toBe('false');
}

async function click(name: string) {
  await act(async () => {
    fireEvent.click(button(name));
  });
}

describe('TPM key cards capability gate', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('withholds the key lifecycle controls the server does not offer', async () => {
    const sent = stubControlPlane({ 'GET /api/v1/capabilities': caps(LIFECYCLE_OPS) });
    render(withControlPlane(<TPMKeyLifecycleCard />));
    fireEvent.change(screen.getByLabelText('Key handle'), { target: { value: '0x81010001' } });
    fireEvent.change(screen.getByLabelText('EK certificate (PEM)'), {
      target: { value: '-----BEGIN CERTIFICATE-----' },
    });

    const names = ['Create EK', 'Evict EK', 'Create SRK', 'Evict SRK', 'Import certificate'];
    for (const name of names) {
      await expectWithheld(name);
    }
    for (const name of names) {
      await click(name);
    }
    expect(sent.filter((r) => r.path.startsWith('/api/v1/tpm/'))).toHaveLength(0);
  });

  it('offers Create SRK when the server enables it', async () => {
    stubControlPlane({ 'GET /api/v1/capabilities': caps() });
    render(withControlPlane(<TPMKeyLifecycleCard />));

    await waitFor(() => expect(button('Create SRK').getAttribute('data-capability-enabled')).toBe('true'));
    expect(button('Create SRK').getAttribute('data-capability-op')).toBe('POST /api/v1/tpm/srk');
  });

  it('withholds Certify and Evict AK when the server does not offer them', async () => {
    const sent = stubControlPlane({ 'GET /api/v1/capabilities': caps(CERTIFY_OPS) });
    render(withControlPlane(<TPMCertifyCard />));
    fireEvent.change(screen.getByLabelText('Key handle'), { target: { value: '0x81000001' } });

    await expectWithheld('Certify');
    await expectWithheld('Evict AK');
    await click('Certify');
    expect(sent.filter((r) => r.method === 'POST' && r.path === '/api/v1/tpm/certify')).toHaveLength(0);
  });

  it('offers Certify when the server enables it', async () => {
    stubControlPlane({ 'GET /api/v1/capabilities': caps() });
    render(withControlPlane(<TPMCertifyCard />));
    fireEvent.change(screen.getByLabelText('Key handle'), { target: { value: '0x81000001' } });

    await waitFor(() => expect(button('Certify').getAttribute('data-capability-enabled')).toBe('true'));
    expect(button('Certify').getAttribute('data-capability-op')).toBe('POST /api/v1/tpm/certify');
  });
});
