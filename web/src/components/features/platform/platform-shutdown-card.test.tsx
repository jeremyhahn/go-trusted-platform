import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, stubControlPlane, withControlPlane, type Answer, type SentRequest } from '@/test/control-plane-fetch';
import { PlatformShutdownCard } from './platform-shutdown-card';

// #2047: the System Health page offers Shutdown (POST /api/v1/platform/shutdown)
// only behind a confirm, and only when the server enables it.

const SHUTDOWN_OP = 'POST /api/v1/platform/shutdown';

// The server's capabilities listing: shutdown enabled unless off.
function caps(off = false): Answer {
  const capabilities = [
    off
      ? { op: SHUTDOWN_OP, kind: 'route', enabled: false, reason: 'not-configured: shutdown' }
      : { op: SHUTDOWN_OP, kind: 'route', enabled: true },
  ];
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

function shutdowns(sent: SentRequest[]): number {
  return sent.filter((r) => r.method === 'POST' && r.path === '/api/v1/platform/shutdown').length;
}

describe('PlatformShutdownCard', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('shutdown asks before it posts', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/capabilities': caps(),
      'POST /api/v1/platform/shutdown': ok({ message: 'shutting down' }),
    });
    render(withControlPlane(<PlatformShutdownCard />));

    const button = await screen.findByRole('button', { name: 'Shut down' });
    await waitFor(() => expect(button.getAttribute('data-capability-enabled')).toBe('true'));
    await act(async () => {
      fireEvent.click(button);
    });
    expect(shutdowns(sent)).toBe(0);

    const confirm = await screen.findByRole('button', { name: 'Shut down the daemon' });
    await act(async () => {
      fireEvent.click(confirm);
    });
    await waitFor(() => expect(shutdowns(sent)).toBe(1));
  });

  it('shutdown is disabled when the server does not enable it', async () => {
    stubControlPlane({
      'GET /api/v1/capabilities': caps(true),
    });
    render(withControlPlane(<PlatformShutdownCard />));

    const button = await screen.findByRole('button', { name: 'Shut down' });
    await waitFor(() => expect(button.getAttribute('data-capability-enabled')).toBe('false'));
    expect((button as HTMLButtonElement).disabled).toBe(true);
  });
});
