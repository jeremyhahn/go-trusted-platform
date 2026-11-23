import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, stubControlPlane, withControlPlane, type Answer, type SentRequest } from '@/test/control-plane-fetch';
import VTPMBundlesPage from './page';

// #2071 (ruling 972): Import bundle is gated on its server op, and the submit
// handler refuses when the server withholds it.

vi.mock('next/navigation', () => ({
  useParams: () => ({}),
  usePathname: () => '/devices/vtpm/bundles',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

const IMPORT_OP = 'POST /api/v1/vtpm/bundles/import';

function caps(off: string[] = []): Answer {
  const capabilities = [IMPORT_OP].map((op) =>
    off.includes(op)
      ? { op, kind: 'route', enabled: false, reason: 'not-configured: vtpm' }
      : { op, kind: 'route', enabled: true },
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

async function renderPage(off: string[] = []): Promise<SentRequest[]> {
  const sent = stubControlPlane({
    'GET /api/v1/vtpm/templates': ok({ templates: [] }),
    'GET /api/v1/vtpm/bundles': ok({ bundles: [], total: 0 }),
    'GET /api/v1/capabilities': caps(off),
    [IMPORT_OP]: ok({ id: 'imported-1', mode: 'pre-assigned' }),
  });
  await act(async () => {
    render(withControlPlane(<VTPMBundlesPage />));
  });
  await screen.findByRole('heading', { level: 1, name: 'vTPM Bundles' });
  return sent;
}

function importButton(): HTMLButtonElement {
  return screen.getByRole('button', { name: 'Import bundle' }) as HTMLButtonElement;
}

describe('VTPM bundles page capability gate', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('Import bundle carries its server op', async () => {
    await renderPage();
    expect(importButton().getAttribute('data-capability-op')).toBe(IMPORT_OP);
    await waitFor(() => expect(importButton().getAttribute('data-capability-enabled')).toBe('true'));
  });

  it('a withheld import op disables Import bundle with the reason and sends nothing', async () => {
    const sent = await renderPage([IMPORT_OP]);
    await waitFor(() => expect(importButton().getAttribute('data-capability-enabled')).toBe('false'));

    const input = document.getElementById('vb-import-file') as HTMLInputElement;
    const archive = new File([new Uint8Array([0x1f, 0x8b])], 'b.tar.gz', { type: 'application/gzip' });
    await act(async () => {
      fireEvent.change(input, { target: { files: [archive] } });
    });

    const button = importButton();
    expect(button.disabled).toBe(true);
    expect(button.getAttribute('title')).toBe('not-configured: vtpm');

    await act(async () => {
      fireEvent.submit(button.closest('form') as HTMLFormElement);
    });
    expect(sent.some((r) => `${r.method} ${r.path}` === IMPORT_OP)).toBe(false);
  });
});
