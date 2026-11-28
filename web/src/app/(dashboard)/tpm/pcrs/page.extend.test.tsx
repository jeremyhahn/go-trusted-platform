import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import TPMPCRsPage from './page';

// The PCR page's Extend PCR control (#2069) runs through the SDK client only
// after the confirm dialog, and is gated on the server's capabilities
// listing: a server that does not offer POST /tpm/pcrs/extend disables it
// with the reason and nothing is sent.

const EXTEND_PATH = 'POST /api/v1/tpm/pcrs/extend';

function caps(off: string[] = []): Answer {
  const capabilities = [EXTEND_PATH, 'GET /api/v1/tpm/pcrs'].map((op) =>
    off.includes(op)
      ? { op, kind: 'route', enabled: false, reason: 'not-configured: tpm' }
      : { op, kind: 'route', enabled: true },
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

function routes(off: string[] = []): Record<string, Answer> {
  return {
    'GET /api/v1/capabilities': caps(off),
    'GET /api/v1/tpm/pcrs': ok({ pcrs: [] }),
    [EXTEND_PATH]: ok({}),
  };
}

function renderPage() {
  render(withControlPlane(<TPMPCRsPage />));
}

async function click(name: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name }));
  });
}

describe('TPMPCRsPage Extend PCR', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('extends PCR 16 only after the confirm', async () => {
    const sent = stubControlPlane(routes());
    renderPage();

    fireEvent.change(screen.getByLabelText('Data'), { target: { value: 'measure-me' } });
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Extend PCR' }).getAttribute('data-capability-enabled')).toBe('true'),
    );
    await click('Extend PCR');
    await screen.findByText('Extend PCR 16?');
    expect(sent.some((r) => r.path === '/api/v1/tpm/pcrs/extend')).toBe(false);

    await click('Confirm');

    await waitFor(() => {
      const extend = sent.find((r) => r.method === 'POST' && r.path === '/api/v1/tpm/pcrs/extend');
      expect(extend?.body).toMatchObject({ index: 16, hashAlg: 'sha256', data: 'bWVhc3VyZS1tZQ==' });
    });
  });

  it('withholds Extend PCR when the server does not offer it', async () => {
    const sent = stubControlPlane(routes([EXTEND_PATH]));
    renderPage();

    fireEvent.change(screen.getByLabelText('Data'), { target: { value: 'measure-me' } });
    await waitFor(() => {
      const button = screen.getByRole('button', { name: 'Extend PCR' }) as HTMLButtonElement;
      expect(button.getAttribute('data-capability-enabled')).toBe('false');
      expect(button.getAttribute('title')).toBe('not-configured: tpm');
      expect(button.disabled).toBe(true);
    });
    await click('Extend PCR');

    expect(screen.queryByText('Extend PCR 16?')).toBeNull();
    expect(sent.some((r) => r.path === '/api/v1/tpm/pcrs/extend')).toBe(false);
  });
});
