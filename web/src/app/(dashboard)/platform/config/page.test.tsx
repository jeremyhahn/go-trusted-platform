import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const { toast } = vi.hoisted(() => ({ toast: vi.fn() }));

vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast }) }));

import ConfigPage from './page';

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
  fetchMock = vi.fn((url: string, opts?: RequestInit) => {
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
    render(<ConfigPage />);
    const button = await screen.findByRole('button', { name: /snapshot/i });
    fireEvent.click(button);
    await waitFor(() => expect((button as HTMLButtonElement).disabled).toBe(false));
    expect(window.prompt).toHaveBeenCalledTimes(1);
    expect(postCalls()).toHaveLength(0);
    expect(toast).not.toHaveBeenCalled();
  });

  it('captures a snapshot with the reason the operator gives', async () => {
    vi.spyOn(window, 'prompt').mockReturnValue('pre-upgrade');
    render(<ConfigPage />);
    const button = await screen.findByRole('button', { name: /snapshot/i });
    fireEvent.click(button);
    await waitFor(() => expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: 'Snapshot captured' })));
    const posts = postCalls();
    expect(posts).toHaveLength(1);
    expect(posts[0][0]).toBe('/api/v1/platform/config/snapshots');
    expect(JSON.parse((posts[0][1] as RequestInit).body as string)).toEqual({ reason: 'pre-upgrade' });
  });

  it('renders the configuration tree once loaded', async () => {
    render(<ConfigPage />);
    expect(await screen.findByText('Configuration Tree')).toBeTruthy();
    expect(screen.getByText(/\/dev\/tpmrm0/)).toBeTruthy();
  });
});
