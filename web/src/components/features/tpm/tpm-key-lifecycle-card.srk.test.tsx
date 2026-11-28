import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { parseHandle } from '@/hooks/use-tpm-key-lifecycle';
import { TPMKeyLifecycleCard } from './tpm-key-lifecycle-card';

// #2068: the TPM key lifecycle card creates and evicts the storage root key
// through the SDK TPMService, evicting only after a confirm.

const SRK = 'POST /api/v1/tpm/srk';
const SRK_DELETE = 'DELETE /api/v1/tpm/srk';

// The card's controls are capability-gated (#2068): the server here offers them all.
const CAPS_OPS = [
  'POST /api/v1/tpm/ek',
  'DELETE /api/v1/tpm/ek',
  'POST /api/v1/tpm/srk',
  'DELETE /api/v1/tpm/srk',
  'POST /api/v1/tpm/ek/certificate',
  'POST /api/v1/tpm/certify',
  'DELETE /api/v1/tpm/ak',
];
const CAPS_ON = ok({
  capabilities: CAPS_OPS.map((op) => ({ op, kind: 'route', enabled: true })),
  total: CAPS_OPS.length,
  enabled: CAPS_OPS.length,
});

async function click(name: string) {
  // A gated control is withheld until the capabilities answer arrives.
  await waitFor(() =>
    expect(screen.getByRole('button', { name }).getAttribute('data-capability-enabled')).not.toBe('false')
  );
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name }));
  });
}

function type(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

describe('TPMKeyLifecycleCard SRK', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('creates a persistent SRK', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/capabilities': CAPS_ON,
      [SRK]: ok({ status: { success: true, message: 'SRK created successfully' }, handle: 2164260865 }),
    });
    render(withControlPlane(<TPMKeyLifecycleCard />));

    await click('Create SRK');

    const toast = await screen.findByText('SRK created: SRK created successfully');
    expect(toast.getAttribute('data-variant')).toBe('success');
    const posts = sent.filter((r) => r.method === 'POST' && r.path === '/api/v1/tpm/srk');
    expect(posts).toHaveLength(1);
    expect(posts[0].body).toEqual({ persistent: true });
    expect(screen.getByTestId('tpm-last-handle').textContent).toContain('0x81000001');
  });

  it('evicts the SRK after the confirm', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/capabilities': CAPS_ON,
      [SRK_DELETE]: ok({ status: { success: true, message: 'SRK evicted' } }),
    });
    render(withControlPlane(<TPMKeyLifecycleCard />));

    type('Key handle', '2164260865');
    await click('Evict SRK');

    const dialog = await screen.findByRole('dialog');
    expect(dialog.textContent).toContain('Evict the SRK?');
    expect(sent.some((r) => r.method === 'DELETE')).toBe(false);

    await click('Evict');

    expect(await screen.findByText('SRK evicted: SRK evicted')).toBeDefined();
    const deletes = sent.filter((r) => r.method === 'DELETE');
    expect(deletes).toHaveLength(1);
    expect(deletes[0]).toEqual({ method: 'DELETE', path: '/api/v1/tpm/srk', body: { handle: 2164260865 } });
  });

  it('sends nothing on Cancel', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/capabilities': CAPS_ON,
      [SRK_DELETE]: ok({ status: { success: true, message: 'SRK evicted' } }),
    });
    render(withControlPlane(<TPMKeyLifecycleCard />));

    await click('Evict SRK');
    await screen.findByRole('dialog');
    await click('Cancel');

    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(sent.some((r) => r.method === 'DELETE')).toBe(false);
  });

  it('shows an unknown handle verbatim', async () => {
    stubControlPlane({
      'GET /api/v1/capabilities': CAPS_ON,
      [SRK_DELETE]: refused(404, 'GetSRK: handle 0x81000009 not found'),
    });
    render(withControlPlane(<TPMKeyLifecycleCard />));

    type('Key handle', '0x81000009');
    await click('Evict SRK');
    await screen.findByRole('dialog');
    await click('Evict');

    const toast = await screen.findByText('SRK evicted failed: GetSRK: handle 0x81000009 not found');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
  });

  it('parses handles', () => {
    expect(parseHandle('0x81000001')).toBe(2164260865);
    expect(parseHandle(' 12 ')).toBe(12);
    expect(parseHandle('')).toBeUndefined();
    expect(Number.isNaN(parseHandle('0xZZ'))).toBe(true);
    expect(Number.isNaN(parseHandle('-1'))).toBe(true);
  });
});
