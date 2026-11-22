import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { TPMKeyLifecycleCard } from './tpm-key-lifecycle-card';

// #2068: the TPM key lifecycle card creates and evicts the endorsement key
// and imports its certificate through the SDK TPMService; an eviction asks
// first, and a refusal reaches the operator verbatim.

const EK = 'POST /api/v1/tpm/ek';
const EK_DELETE = 'DELETE /api/v1/tpm/ek';
const EK_CERT = 'POST /api/v1/tpm/ek/certificate';

async function click(name: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name }));
  });
}

function type(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

describe('TPMKeyLifecycleCard EK', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('creates a persistent EK', async () => {
    const sent = stubControlPlane({
      [EK]: ok({
        status: { success: true, message: 'EK created successfully' },
        publicKey: 'AQID',
        handle: 2164326401,
      }),
    });
    render(withControlPlane(<TPMKeyLifecycleCard />));

    await click('Create EK');

    const toast = await screen.findByText('EK created: EK created successfully');
    expect(toast.getAttribute('data-variant')).toBe('success');
    const posts = sent.filter((r) => r.method === 'POST' && r.path === '/api/v1/tpm/ek');
    expect(posts).toHaveLength(1);
    expect(posts[0].body).toEqual({ persistent: true });
    expect(screen.getByTestId('tpm-last-handle').textContent).toContain('0x81010001');
  });

  it('evicts the EK only after the confirm', async () => {
    const sent = stubControlPlane({
      [EK_DELETE]: ok({ status: { success: true, message: 'EK evicted' } }),
    });
    render(withControlPlane(<TPMKeyLifecycleCard />));

    type('Key handle', '0x81010001');
    await click('Evict EK');

    const dialog = await screen.findByRole('dialog');
    expect(dialog.textContent).toContain('Evict the EK?');
    expect(sent.some((r) => r.method === 'DELETE')).toBe(false);

    await click('Evict');

    expect(await screen.findByText('EK evicted: EK evicted')).toBeDefined();
    const deletes = sent.filter((r) => r.method === 'DELETE');
    expect(deletes).toHaveLength(1);
    expect(deletes[0]).toEqual({ method: 'DELETE', path: '/api/v1/tpm/ek', body: { handle: 2164326401 } });
  });

  it('sends nothing on Cancel or a bad handle', async () => {
    const sent = stubControlPlane({
      [EK_DELETE]: ok({ status: { success: true, message: 'EK evicted' } }),
    });
    render(withControlPlane(<TPMKeyLifecycleCard />));

    type('Key handle', 'zz');
    await click('Evict EK');
    const toast = await screen.findByText('Invalid handle: a handle is a hex (0x...) or decimal number');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(screen.queryByRole('dialog')).toBeNull();

    type('Key handle', '');
    await click('Evict EK');
    await screen.findByRole('dialog');
    await click('Cancel');

    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(sent.some((r) => r.method === 'DELETE')).toBe(false);
  });

  it('imports a pasted PEM certificate', async () => {
    const sent = stubControlPlane({
      [EK_CERT]: ok({ status: { success: true, message: 'EK certificate imported successfully' } }),
    });
    render(withControlPlane(<TPMKeyLifecycleCard />));

    type('EK certificate (PEM)', '-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----');
    await click('Import certificate');

    const toast = await screen.findByText('EK certificate imported: EK certificate imported successfully');
    expect(toast.getAttribute('data-variant')).toBe('success');
    const posts = sent.filter((r) => r.path === '/api/v1/tpm/ek/certificate');
    expect(posts).toHaveLength(1);
    const body = posts[0].body as { certificate: string; format: string };
    expect(body.format).toBe('PEM');
    expect(atob(body.certificate).startsWith('-----BEGIN CERTIFICATE-----')).toBe(true);
  });

  it('shows a refusal verbatim and needs a certificate', async () => {
    const sent = stubControlPlane({
      [EK]: refused(409, 'EK already exists at 0x81010001'),
    });
    render(withControlPlane(<TPMKeyLifecycleCard />));

    await click('Import certificate');
    const required = await screen.findByText('Certificate required: paste the PEM certificate');
    expect(required.getAttribute('data-variant')).toBe('destructive');
    expect(sent).toHaveLength(0);

    await click('Create EK');
    const toast = await screen.findByText('EK created failed: EK already exists at 0x81010001');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
  });
});
