import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { TPMCertifyCard } from './tpm-certify-card';

// #2068: the card evicts the AK at a persistent handle (DELETE
// /api/v1/tpm/ak through the SDK) only after a confirm; the server refuses
// to evict the IAK, and that refusal reaches the operator verbatim.

const DELETE_AK = 'DELETE /api/v1/tpm/ak';

function type(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

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

function deletes(sent: { method: string }[]) {
  return sent.filter((r) => r.method === 'DELETE');
}

describe('TPMCertifyCard Evict AK', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('asks before evicting and sends nothing on Cancel', async () => {
    const sent = stubControlPlane({ 'GET /api/v1/capabilities': CAPS_ON, [DELETE_AK]: ok({}) });
    render(withControlPlane(<TPMCertifyCard />));
    type('Key handle', '0x81010002');
    await click('Evict AK');

    const dialog = await screen.findByRole('dialog');
    expect(dialog.textContent).toContain('Evict the AK?');
    await click('Cancel');
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(deletes(sent)).toHaveLength(0);
  });

  it('shows the IAK refusal verbatim', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/capabilities': CAPS_ON,
      [DELETE_AK]: refused(409, 'IAK is a device identity key and cannot be deleted'),
    });
    render(withControlPlane(<TPMCertifyCard />));
    type('Key handle', '0x81010002');
    await click('Evict AK');
    await screen.findByRole('dialog');
    await click('Evict');

    const toast = await screen.findByText(
      'Evict AK refused: IAK is a device identity key and cannot be deleted'
    );
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(deletes(sent)).toHaveLength(1);
    expect((sent.find((r) => r.method === 'DELETE') as { body: unknown }).body).toEqual({
      handle: 2164326402,
    });
  });

  it('evicts when the server allows it', async () => {
    stubControlPlane({ 'GET /api/v1/capabilities': CAPS_ON, [DELETE_AK]: ok({ status: { success: true, message: 'AK evicted' } }) });
    render(withControlPlane(<TPMCertifyCard />));
    type('Key handle', '0x81010002');
    await click('Evict AK');
    await screen.findByRole('dialog');
    await click('Evict');

    const toast = await screen.findByText('AK evicted: AK evicted');
    expect(toast.getAttribute('data-variant')).toBe('success');
  });

  it('refuses a bad handle without a dialog', async () => {
    const sent = stubControlPlane({ 'GET /api/v1/capabilities': CAPS_ON, [DELETE_AK]: ok({}) });
    render(withControlPlane(<TPMCertifyCard />));
    type('Key handle', 'zz');
    await click('Evict AK');

    const toast = await screen.findByText(
      'Invalid handle: a persistent handle is 0x81000000-0x81FFFFFF'
    );
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(deletes(sent)).toHaveLength(0);
  });
});
