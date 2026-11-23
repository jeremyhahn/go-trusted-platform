import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import { PXEServiceControls } from './pxe-service-controls';

vi.mock('next/navigation', () => ({
  useParams: () => ({}),
  usePathname: () => '/networking/pxe',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const START = 'POST /api/v1/pxe/start';
const STOP = 'POST /api/v1/pxe/stop';
const PXE_OPS = [START, STOP];

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
    'POST /api/v1/pxe/start': ok({ status: 'ok' }),
    'POST /api/v1/pxe/stop': ok({ status: 'ok' }),
    ...extra,
  };
}

function renderControls(running: boolean, onChanged: () => void) {
  render(withControlPlane(<PXEServiceControls running={running} onChanged={onChanged} />));
}

async function click(name: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name }));
  });
}

function writes(sent: { method: string; path: string }[]) {
  return sent.filter((r) => r.path.startsWith('/api/v1/pxe/'));
}

async function capabilitiesLoaded(sent: { method: string; path: string }[], name: string, op: string) {
  await waitFor(() => expect(sent.some((r) => r.path === '/api/v1/capabilities')).toBe(true));
  await waitFor(() => expect(screen.getByRole('button', { name }).getAttribute('data-capability-op')).toBe(op));
}

function toastsOf(variant: string) {
  return screen.getAllByTestId('toast').filter((t) => t.getAttribute('data-variant') === variant);
}

describe('PXEServiceControls', () => {
  it('starts a stopped service', async () => {
    const sent = stubControlPlane(routes());
    const onChanged = vi.fn();
    renderControls(false, onChanged);
    await capabilitiesLoaded(sent, 'Start PXE service', START);
    expect(screen.queryByRole('button', { name: 'Stop PXE service' })).toBeNull();

    await click('Start PXE service');

    await waitFor(() => expect(onChanged).toHaveBeenCalledTimes(1));
    expect(writes(sent).map((r) => `${r.method} ${r.path}`)).toEqual(['POST /api/v1/pxe/start']);
    await waitFor(() => expect(toastsOf('success').length).toBeGreaterThan(0));
  });

  it('stops a running service only after the confirm', async () => {
    const sent = stubControlPlane(routes());
    const onChanged = vi.fn();
    renderControls(true, onChanged);
    await capabilitiesLoaded(sent, 'Stop PXE service', STOP);
    expect(screen.queryByRole('button', { name: 'Start PXE service' })).toBeNull();

    await click('Stop PXE service');
    expect(writes(sent)).toEqual([]);
    expect(screen.getByText('Stop PXE service?')).toBeTruthy();

    await click('Stop');

    await waitFor(() => expect(onChanged).toHaveBeenCalledTimes(1));
    expect(writes(sent).map((r) => `${r.method} ${r.path}`)).toEqual(['POST /api/v1/pxe/stop']);
  });

  it('withholds the control the server does not offer', async () => {
    const sent = stubControlPlane(routes({}, [START, STOP]));
    const onChanged = vi.fn();
    renderControls(false, onChanged);
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Start PXE service' }).getAttribute('data-capability-enabled')).toBe(
        'false',
      ),
    );
    const button = screen.getByRole('button', { name: 'Start PXE service' }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    expect(button.getAttribute('title')).toBe('not-configured: pxe');

    await act(async () => {
      fireEvent.click(button);
    });
    expect(writes(sent)).toEqual([]);
    expect(onChanged).not.toHaveBeenCalled();
  });

  it('shows a refused start as a destructive toast', async () => {
    const sent = stubControlPlane(routes({ 'POST /api/v1/pxe/start': refused(409, 'already running') }));
    const onChanged = vi.fn();
    renderControls(false, onChanged);
    await capabilitiesLoaded(sent, 'Start PXE service', START);

    await click('Start PXE service');

    await waitFor(() =>
      expect(
        toastsOf('destructive')
          .map((t) => t.textContent)
          .join(' '),
      ).toContain('already running'),
    );
    expect(onChanged).not.toHaveBeenCalled();
  });
});
