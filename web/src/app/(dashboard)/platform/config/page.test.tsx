import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const { toast } = vi.hoisted(() => ({ toast: vi.fn() }));

vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast }) }));

import type { ReactNode } from 'react';
import { PlatformProvider } from 'trusted-platform-sdk';
import ConfigPage from './page';

// The page's write controls are capability-gated (#2047), so it renders
// inside the PlatformProvider and the stub answers GET /api/v1/capabilities.
function withPlatform(children: ReactNode) {
  return <PlatformProvider config={{ baseUrl: '/api' }}><>{children}</></PlatformProvider>;
}

const capabilitiesBody = {
  capabilities: [
    { op: 'POST /api/v1/platform/config/reload', kind: 'route', enabled: true },
    { op: 'PUT /api/v1/platform/config/sections/{section}', kind: 'route', enabled: true },
  ],
  total: 2,
  enabled: 2,
};

const configBody = {
  payload: {
    sources: [],
    tree: { tpm: { device: '/dev/tpmrm0' } },
    generated_at: '2026-01-01T00:00:00Z',
    secrets_hidden: false,
  },
};

let fetchMock: ReturnType<typeof vi.fn>;

function reply(body: unknown): Promise<unknown> {
  return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body), text: () => Promise.resolve('') });
}

function postCalls() {
  return fetchMock.mock.calls.filter(([, o]) => (o as RequestInit | undefined)?.method === 'POST');
}

beforeEach(() => {
  toast.mockReset();
  fetchMock = vi.fn((input: RequestInfo | URL, opts?: RequestInit) => {
    const url = input instanceof Request ? input.url : String(input);
    if (url.endsWith('/api/v1/capabilities')) {
      return Promise.resolve(
        new Response(JSON.stringify(capabilitiesBody), { status: 200, headers: { 'Content-Type': 'application/json' } })
      );
    }
    if (url === '/api/v1/platform/config/snapshots' && opts?.method === 'POST') {
      return reply({ payload: { id: 'snap-1' } });
    }
    if (url === '/api/v1/platform/config/snapshots') {
      return reply({ payload: { snapshots: [] } });
    }
    return reply(configBody);
  });
  vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('ConfigPage', () => {
  it('captures no snapshot when the reason prompt is cancelled', async () => {
    vi.spyOn(window, 'prompt').mockReturnValue(null);
    render(withPlatform(<ConfigPage />));
    const button = await screen.findByRole('button', { name: /snapshot/i });
    fireEvent.click(button);
    await waitFor(() => expect((button as HTMLButtonElement).disabled).toBe(false));
    expect(window.prompt).toHaveBeenCalledTimes(1);
    expect(postCalls()).toHaveLength(0);
    expect(toast).not.toHaveBeenCalled();
  });

  it('captures a snapshot with the reason the operator gives', async () => {
    vi.spyOn(window, 'prompt').mockReturnValue('pre-upgrade');
    render(withPlatform(<ConfigPage />));
    const button = await screen.findByRole('button', { name: /snapshot/i });
    fireEvent.click(button);
    await waitFor(() => expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: 'Snapshot captured' })));
    const posts = postCalls();
    expect(posts).toHaveLength(1);
    expect(posts[0][0]).toBe('/api/v1/platform/config/snapshots');
    expect(JSON.parse((posts[0][1] as RequestInit).body as string)).toEqual({ reason: 'pre-upgrade' });
  });

  it('renders the configuration tree once loaded', async () => {
    render(withPlatform(<ConfigPage />));
    expect(await screen.findByText('Configuration Tree')).toBeTruthy();
    expect(screen.getByText(/\/dev\/tpmrm0/)).toBeTruthy();
  });
});
