import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import VTPMDetailPage from './vtpm-detail-client';

// #2071: the vTPM bundle page seals and unseals through the bundle runtime
// routes, deletes through its route, and gates each control on the server's
// capabilities. Reset has no server route and stays disabled.

const push = vi.fn();

vi.mock('next/navigation', () => ({
  useParams: () => ({ id: 'b-1' }),
  usePathname: () => '/devices/vtpm/b-1/',
  useRouter: () => ({ push, back: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
}));

const SEAL = 'POST /api/v1/vtpm/bundles/{id}/seal';
const UNSEAL = 'POST /api/v1/vtpm/bundles/{id}/unseal';
const DELETE = 'DELETE /api/v1/vtpm/bundles/{id}';
const OPS = [DELETE, SEAL, UNSEAL];

// The server's capabilities answer: every op on except those in off.
function caps(off: string[] = []): Answer {
  const capabilities = OPS.map((op) =>
    off.includes(op)
      ? { op, kind: 'route', enabled: false, reason: 'not-configured: vtpm' }
      : { op, kind: 'route', enabled: true },
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

const bundle = {
  id: 'b-1',
  name: 'vm-1-vtpm',
  state: 'active',
  vmId: 'vm-1',
  vmName: 'vm-1',
  pcrProfile: 'default',
  createdAt: '2026-01-01T00:00:00Z',
  pcrValues: [],
  sealedData: [],
  migrations: [],
};

function routes(extra: Record<string, Answer> = {}, off: string[] = []): Record<string, Answer> {
  return {
    'GET /api/v1/capabilities': caps(off),
    'GET /api/v1/vtpm/bundles/b-1': ok(bundle),
    'GET /api/v1/vtpm/bundles/b-1/state': ok({ running: true }),
    'POST /api/v1/vtpm/bundles/b-1/seal': ok({ status: 'ok', bundle_id: 'b-1', sealed_data: 'c2VhbGVk' }),
    'POST /api/v1/vtpm/bundles/b-1/unseal': ok({ data: 'aGVsbG8=' }),
    'DELETE /api/v1/vtpm/bundles/b-1': ok({}),
    ...extra,
  };
}

const headerButton = (name: string) => screen.getAllByRole('button', { name })[0] as HTMLButtonElement;

async function renderPage() {
  render(withControlPlane(<VTPMDetailPage />));
  await screen.findByRole('heading', { level: 1, name: 'vm-1-vtpm' });
}

async function waitForCaps(name: string, enabled: 'true' | 'false') {
  await waitFor(() => expect(headerButton(name).getAttribute('data-capability-enabled')).toBe(enabled));
}

function noStubToast() {
  for (const t of screen.queryAllByTestId('toast')) {
    expect(t.textContent ?? '').not.toMatch(/not yet implemented/);
  }
}

describe('VTPMDetailPage', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    push.mockReset();
  });

  it('seals the typed data through the seal route', async () => {
    const sent = stubControlPlane(routes());
    await renderPage();
    await waitForCaps('Seal Data', 'true');

    await act(async () => {
      fireEvent.click(headerButton('Seal Data'));
    });
    const dialog = await screen.findByRole('dialog');
    fireEvent.change(within(dialog).getByLabelText('Name'), { target: { value: 'secret' } });
    fireEvent.change(within(dialog).getByLabelText('Data to Seal'), { target: { value: 'hello' } });
    fireEvent.change(within(dialog).getByLabelText('PCR Indices (comma-separated)'), { target: { value: '0,7' } });
    await act(async () => {
      fireEvent.click(within(dialog).getByRole('button', { name: 'Seal Data' }));
    });

    await waitFor(() => expect(screen.getByTestId('vtpm-sealed-blob').textContent).toContain('c2VhbGVk'));
    const req = sent.find((r) => r.method === 'POST' && r.path === '/api/v1/vtpm/bundles/b-1/seal');
    expect(req).toBeDefined();
    expect(req?.body).toMatchObject({ data: btoa('hello'), pcrs: [0, 7] });
    noStubToast();
  });

  it('unseals a pasted blob through the unseal route', async () => {
    const sent = stubControlPlane(routes());
    await renderPage();
    await waitForCaps('Unseal', 'true');

    await act(async () => {
      fireEvent.click(headerButton('Unseal'));
    });
    const dialog = await screen.findByRole('dialog');
    fireEvent.change(within(dialog).getByLabelText('Sealed blob to unseal'), { target: { value: 'c2VhbGVk' } });
    await act(async () => {
      fireEvent.click(within(dialog).getByRole('button', { name: 'Unseal blob' }));
    });

    await waitFor(() => expect(screen.getByTestId('vtpm-unsealed-data').textContent).toContain('hello'));
    const req = sent.find((r) => r.method === 'POST' && r.path === '/api/v1/vtpm/bundles/b-1/unseal');
    expect(req?.body).toMatchObject({ sealed_data: 'c2VhbGVk' });
    noStubToast();
  });

  it('deletes the bundle after the confirm', async () => {
    vi.stubGlobal('confirm', () => true);
    const sent = stubControlPlane(routes());
    await renderPage();
    await waitForCaps('Delete', 'true');

    await act(async () => {
      fireEvent.click(headerButton('Delete'));
    });

    await waitFor(() => expect(push).toHaveBeenCalledWith('/devices/vtpm'));
    expect(sent.some((r) => r.method === 'DELETE' && r.path === '/api/v1/vtpm/bundles/b-1')).toBe(true);
  });

  it('withholds the controls the server does not offer', async () => {
    vi.stubGlobal('confirm', () => true);
    const sent = stubControlPlane(routes({}, OPS));
    await renderPage();
    // Wait for the capabilities answer (the gate reads every op as off until it lands).
    await waitFor(() => expect(headerButton('Delete').getAttribute('title')).toBe('not-configured: vtpm'));

    for (const name of ['Seal Data', 'Unseal', 'Delete']) {
      const b = headerButton(name);
      expect(b.disabled).toBe(true);
      expect(b.getAttribute('title')).toBe('not-configured: vtpm');
      expect(b.getAttribute('data-capability-enabled')).toBe('false');
      await act(async () => {
        fireEvent.click(b);
      });
    }
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(sent.some((r) => r.method !== 'GET')).toBe(false);
  });

  it('shows Reset as unavailable', async () => {
    stubControlPlane(routes());
    await renderPage();
    const reset = headerButton('Reset');
    expect(reset.disabled).toBe(true);
    expect(reset.getAttribute('title')).toBe('No server route');
  });

  it('shows a refused seal as a destructive toast', async () => {
    stubControlPlane(routes({ 'POST /api/v1/vtpm/bundles/b-1/seal': refused(409, 'bundle not running') }));
    await renderPage();
    await waitForCaps('Seal Data', 'true');

    await act(async () => {
      fireEvent.click(headerButton('Seal Data'));
    });
    const dialog = await screen.findByRole('dialog');
    fireEvent.change(within(dialog).getByLabelText('Name'), { target: { value: 'secret' } });
    fireEvent.change(within(dialog).getByLabelText('Data to Seal'), { target: { value: 'hello' } });
    await act(async () => {
      fireEvent.click(within(dialog).getByRole('button', { name: 'Seal Data' }));
    });

    await waitFor(() => {
      const toast = screen.getAllByTestId('toast').find((t) => (t.textContent ?? '').includes('bundle not running'));
      expect(toast?.getAttribute('data-variant')).toBe('destructive');
    });
    expect(screen.queryByTestId('vtpm-sealed-blob')).toBeNull();
  });
});
