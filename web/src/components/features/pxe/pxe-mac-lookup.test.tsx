import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import { PXEMacLookup } from './pxe-mac-lookup';

const push = vi.hoisted(() => vi.fn());

vi.mock('next/navigation', () => ({
  useParams: () => ({}),
  usePathname: () => '/networking/pxe',
  useRouter: () => ({ push, back: vi.fn() }),
}));

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  push.mockClear();
});

const BY_MAC = 'GET /api/v1/pxe/devices/mac/{mac}';
const PXE_OPS = [BY_MAC];
const MAC = '02:00:00:00:00:01';
const MAC_ROUTE = 'GET /api/v1/pxe/devices/mac/02%3A00%3A00%3A00%3A00%3A01';

function caps(off: string[] = []): Answer {
  const capabilities = PXE_OPS.map((op) =>
    off.includes(op)
      ? { op, kind: 'route', enabled: false, reason: 'not-configured: pxe' }
      : { op, kind: 'route', enabled: true },
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

function routes(extra: Record<string, Answer> = {}, off: string[] = []): Record<string, Answer> {
  return {
    'GET /api/v1/capabilities': caps(off),
    [MAC_ROUTE]: ok({ device: { id: 'dev-1', macAddress: MAC, state: 'DISCOVERED' } }),
    ...extra,
  };
}

function lookups(sent: { method: string; path: string }[]) {
  return sent.filter((r) => r.path.startsWith('/api/v1/pxe/'));
}

async function capabilitiesLoaded(sent: { method: string; path: string }[], name: string, op: string) {
  await waitFor(() => expect(sent.some((r) => r.path === '/api/v1/capabilities')).toBe(true));
  await waitFor(() => expect(screen.getByRole('button', { name }).getAttribute('data-capability-op')).toBe(op));
}

function toastsOf(variant: string) {
  return screen.getAllByTestId('toast').filter((t) => t.getAttribute('data-variant') === variant);
}

function typeMac(value: string) {
  fireEvent.change(screen.getByLabelText('MAC address'), { target: { value } });
}

async function clickFind() {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Find by MAC' }));
  });
}

describe('PXEMacLookup', () => {
  it('opens the detail page of the device the server finds', async () => {
    const sent = stubControlPlane(routes());
    render(withControlPlane(<PXEMacLookup />));
    await capabilitiesLoaded(sent, 'Find by MAC', BY_MAC);

    typeMac(MAC);
    await clickFind();

    await waitFor(() => expect(push).toHaveBeenCalledTimes(1));
    expect(push).toHaveBeenCalledWith('/networking/pxe/dev-1');
    expect(lookups(sent).map((r) => `${r.method} ${r.path}`)).toEqual([MAC_ROUTE]);
  });

  it('does not send an empty MAC', async () => {
    const sent = stubControlPlane(routes());
    render(withControlPlane(<PXEMacLookup />));
    await capabilitiesLoaded(sent, 'Find by MAC', BY_MAC);

    const button = screen.getByRole('button', { name: 'Find by MAC' }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    typeMac('   ');
    expect(button.disabled).toBe(true);
    await clickFind();

    expect(lookups(sent)).toEqual([]);
    expect(push).not.toHaveBeenCalled();
  });

  it('withholds the lookup the server does not offer', async () => {
    const sent = stubControlPlane(routes({}, [BY_MAC]));
    render(withControlPlane(<PXEMacLookup />));
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Find by MAC' }).getAttribute('data-capability-enabled')).toBe('false'),
    );
    typeMac(MAC);
    const button = screen.getByRole('button', { name: 'Find by MAC' }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    expect(button.getAttribute('title')).toBe('not-configured: pxe');

    await clickFind();
    expect(lookups(sent)).toEqual([]);
    expect(push).not.toHaveBeenCalled();
  });

  it('shows a MAC the server does not know as a destructive toast', async () => {
    const sent = stubControlPlane(routes({ [MAC_ROUTE]: refused(404, 'device not found') }));
    render(withControlPlane(<PXEMacLookup />));
    await capabilitiesLoaded(sent, 'Find by MAC', BY_MAC);

    typeMac(MAC);
    await clickFind();

    await waitFor(() =>
      expect(
        toastsOf('destructive')
          .map((t) => t.textContent)
          .join(' '),
      ).toContain('device not found'),
    );
    expect(push).not.toHaveBeenCalled();
  });
});
