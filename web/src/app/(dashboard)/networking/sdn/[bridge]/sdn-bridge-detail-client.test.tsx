import type { ReactNode } from 'react';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { type Answer, ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import SDNBridgeDetailClient from './sdn-bridge-detail-client';

// #1755 Codex round 2: a refused SDK call (ApiResponse.success false) is a
// failure, never a success toast, and the port certificate travels as the
// base64 of the PEM bytes (AuthenticatePortRequest.certificate is bytes).

const push = vi.fn();

vi.mock('next/navigation', () => ({
  useParams: () => ({ bridge: 'br-1' }),
  usePathname: () => '/networking/sdn/br-1',
  useRouter: () => ({ push, back: vi.fn(), replace: vi.fn() }),
}));

vi.mock('@/components/ui/dialog', () => ({
  Dialog: ({ open, children }: { open: boolean; children: ReactNode }) =>
    open ? <div role="dialog">{children}</div> : null,
  DialogContent: ({ children }: { children: ReactNode }) => <>{children}</>,
  DialogHeader: ({ children }: { children: ReactNode }) => <>{children}</>,
  DialogFooter: ({ children }: { children: ReactNode }) => <>{children}</>,
  DialogTitle: ({ children }: { children: ReactNode }) => <>{children}</>,
  DialogDescription: ({ children }: { children: ReactNode }) => <>{children}</>,
}));

const SDN = '/api/v1/sdn';
const AUTH_PATH = `${SDN}/bridges/br-1/ports/p-1/auth`;
const PEM = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----';

async function renderPage(extra: Record<string, Answer>) {
  const sent = stubControlPlane({
    [`GET ${SDN}/bridges/br-1`]: ok({
      bridge: { id: 'br-1', config: { name: 'br-int' }, status: 'BRIDGE_STATUS_UP' },
    }),
    [`GET ${SDN}/bridges/br-1/ports`]: ok({
      ports: [
        {
          id: 'p-1',
          bridgeId: 'br-1',
          config: { name: 'eth1' },
          status: 'PORT_STATUS_UP',
          auth: { authenticated: false },
        },
      ],
    }),
    [`GET ${SDN}/policies`]: ok({ policies: [] }),
    [`GET ${SDN}/bridges/br-1/ports/p-1/state`]: ok({}),
    [`GET ${SDN}/bridges/br-1/ports/p-1/stats`]: ok({}),
    ...extra,
  });
  render(withControlPlane(<SDNBridgeDetailClient />));
  await screen.findByRole('heading', { level: 1, name: 'br-int' });
  return sent;
}

async function authenticate(pem: string) {
  fireEvent.click(await screen.findByRole('button', { name: 'Manage port eth1' }));
  fireEvent.change(await screen.findByLabelText('Certificate (PEM)'), { target: { value: pem } });
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Authenticate Port' }));
  });
}

function toasts() {
  return screen.queryAllByTestId('toast');
}

describe('SDNBridgeDetailClient refused calls and certificate encoding', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    push.mockReset();
  });

  it('a refused bridge delete shows the failure and stays on the page', async () => {
    await renderPage({ [`DELETE ${SDN}/bridges/br-1`]: refused(500, 'bridge busy') });

    fireEvent.click(screen.getByRole('button', { name: 'Delete Bridge' }));
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Confirm Delete' }));
    });

    await waitFor(() => {
      const failed = toasts().find((t) => t.getAttribute('data-variant') === 'destructive');
      expect(failed?.textContent).toContain('Bridge deleted failed');
      expect(failed?.textContent).toContain('bridge busy');
    });
    expect(toasts().some((t) => t.getAttribute('data-variant') === 'success')).toBe(false);
    expect(push).not.toHaveBeenCalled();
  });

  it('a refused port authentication is not reported as success', async () => {
    await renderPage({ [`POST ${AUTH_PATH}`]: refused(412, 'port authentication is not enforced') });

    await authenticate(PEM);

    await waitFor(() => {
      const failed = toasts().find((t) => t.getAttribute('data-variant') === 'destructive');
      expect(failed?.textContent).toContain('Port authenticated failed');
      expect(failed?.textContent).toContain('port authentication is not enforced');
    });
    expect(toasts().some((t) => t.textContent?.startsWith('Port authenticated:'))).toBe(false);
  });

  it('the certificate is sent as base64 of the PEM bytes', async () => {
    const sent = await renderPage({ [`POST ${AUTH_PATH}`]: ok({}) });

    await authenticate(PEM);

    await waitFor(() => expect(sent.some((r) => r.method === 'POST' && r.path === AUTH_PATH)).toBe(true));
    const body = sent.find((r) => r.method === 'POST' && r.path === AUTH_PATH)?.body as {
      certificate: string;
      format: string;
    };
    expect(atob(body.certificate)).toBe(PEM);
    expect(body.format).toBe('PEM');
  });
});
