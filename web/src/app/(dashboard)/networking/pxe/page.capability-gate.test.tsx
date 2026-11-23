import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import PXEBootPage from './page';

vi.mock('next/navigation', () => ({
  useParams: () => ({}),
  usePathname: () => '/networking/pxe',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const REGISTER = 'POST /api/v1/pxe/devices';

function caps(off: string[] = []): Answer {
  const capabilities = [REGISTER].map((op) =>
    off.includes(op)
      ? { op, kind: 'route', enabled: false, reason: 'not-configured: pxe' }
      : { op, kind: 'route', enabled: true },
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

function routes(extra: Record<string, Answer> = {}, off: string[] = []): Record<string, Answer> {
  return {
    'GET /api/v1/capabilities': caps(off),
    'GET /api/v1/pxe/devices': ok({ devices: [] }),
    'GET /api/v1/pxe/status': ok({ status: { running: false } }),
    'POST /api/v1/pxe/devices': ok({ device: { id: 'd1', macAddress: '02:00:00:00:00:01' } }),
    ...extra,
  };
}

async function registerButton(enabled: 'true' | 'false'): Promise<HTMLElement> {
  const button = await screen.findByRole('button', { name: /Register Device/ });
  await waitFor(() => expect(button.getAttribute('data-capability-enabled')).toBe(enabled));
  return button;
}

async function openDialog(): Promise<void> {
  const button = await screen.findByRole('button', { name: /Register Device/ });
  await waitFor(() => expect(button.hasAttribute('disabled')).toBe(false));
  await act(async () => {
    fireEvent.click(button);
  });
  await screen.findByText('Register PXE Device');
}

function successToasts(): HTMLElement[] {
  return screen.queryAllByTestId('toast').filter((t) => t.getAttribute('data-variant') === 'success');
}

function dialogRegister(): HTMLElement {
  return screen.getByRole('button', { name: /^Register$/ });
}

describe('PXEBootPage register gate', () => {
  it('withholds Register Device with the server reason', async () => {
    const sent = stubControlPlane(routes({}, [REGISTER]));
    render(withControlPlane(<PXEBootPage />));

    await waitFor(() => expect(sent.some((r) => r.method === 'GET' && r.path === '/api/v1/capabilities')).toBe(true));
    const button = await registerButton('false');
    expect(button.hasAttribute('disabled')).toBe(true);
    expect(button.getAttribute('title')).toBe('not-configured: pxe');
    expect(button.getAttribute('data-capability-op')).toBe(REGISTER);

    await act(async () => {
      fireEvent.click(button);
    });
    expect(screen.queryByText('Register PXE Device')).toBeNull();
  });

  it('asks the gate for the register op and opens the dialog when offered', async () => {
    stubControlPlane(routes());
    render(withControlPlane(<PXEBootPage />));

    const button = await registerButton('true');
    expect(button.getAttribute('data-capability-op')).toBe(REGISTER);
    await openDialog();
    expect(dialogRegister().getAttribute('data-capability-op')).toBe(REGISTER);
  });

  it('registers the typed MAC through the SDK', async () => {
    const sent = stubControlPlane(routes());
    render(withControlPlane(<PXEBootPage />));

    await openDialog();
    fireEvent.change(screen.getByLabelText('MAC Address *'), { target: { value: '02:00:00:00:00:01' } });
    await act(async () => {
      fireEvent.click(dialogRegister());
    });

    await waitFor(() => expect(sent.some((r) => r.method === 'POST' && r.path === '/api/v1/pxe/devices')).toBe(true));
    await waitFor(() =>
      expect(screen.getAllByTestId('toast').some((t) => t.getAttribute('data-variant') === 'success')).toBe(true),
    );
  });

  it('shows a refused register as a destructive toast and keeps the dialog open', async () => {
    stubControlPlane(routes({ 'POST /api/v1/pxe/devices': refused(409, 'device already registered') }));
    render(withControlPlane(<PXEBootPage />));

    await openDialog();
    fireEvent.change(screen.getByLabelText('MAC Address *'), { target: { value: '02:00:00:00:00:01' } });
    // The toast store is module state, so a success toast from an earlier case may still be listed.
    const successBefore = successToasts();
    await act(async () => {
      fireEvent.click(dialogRegister());
    });

    await waitFor(() => {
      const destructive = screen
        .getAllByTestId('toast')
        .filter((t) => t.getAttribute('data-variant') === 'destructive');
      expect(destructive.some((t) => (t.textContent ?? '').includes('device already registered'))).toBe(true);
    });
    expect(successToasts().filter((t) => !successBefore.includes(t))).toEqual([]);
    expect(screen.getByText('Register PXE Device')).toBeTruthy();
  });
});
