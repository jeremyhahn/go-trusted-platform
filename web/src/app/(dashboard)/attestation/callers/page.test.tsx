import { cleanup, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import CallerPolicyPage from './page';

// #2038: the caller policy page reads DescribeCallerPolicy
// (GET /api/v1/attestation/callers) through the real SDK client on
// client.attestation, and only when the server offers the route.

vi.mock('next/navigation', () => ({
  useParams: () => ({}),
  usePathname: () => '/attestation/callers',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const OP = 'GET /api/v1/attestation/callers';

// The server's capabilities listing: the caller policy op, off when off is set.
function caps(off = false): Answer {
  const capabilities = [
    off ? { op: OP, kind: 'route', enabled: false, reason: 'not-configured: attestation' } : { op: OP, kind: 'route', enabled: true },
  ];
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

function count(sent: { method: string; path: string }[], method: string, path: string) {
  return sent.filter((r) => r.method === method && r.path === path).length;
}

describe('CallerPolicyPage', () => {
  it('shows the caller policy the server answers', async () => {
    stubControlPlane({
      'GET /api/v1/capabilities': caps(),
      [OP]: ok({
        strategy: 'allowlist',
        identities: ['spiffe://example.test/node/a'],
        identities_source: 'config',
        list_valid: true,
        anchors_configured: true,
        anchor_source: 'ca',
        attested_peers_available: false,
        admits_nobody: false,
      }),
    });
    render(withControlPlane(<CallerPolicyPage />));

    expect(await screen.findByText('allowlist')).toBeTruthy();
    expect(screen.getByText('spiffe://example.test/node/a')).toBeTruthy();
    expect(screen.getByText('config')).toBeTruthy();
    expect(screen.getByText('ca')).toBeTruthy();
    expect(screen.queryByTestId('caller-admits-nobody')).toBeNull();
  });

  it('warns when the policy admits no caller', async () => {
    stubControlPlane({
      'GET /api/v1/capabilities': caps(),
      [OP]: ok({
        strategy: 'allowlist',
        identities: [],
        list_valid: false,
        invalid_entries: ['bad entry'],
        anchors_configured: false,
        attested_peers_available: false,
        admits_nobody: true,
      }),
    });
    render(withControlPlane(<CallerPolicyPage />));

    expect(await screen.findByTestId('caller-admits-nobody')).toBeTruthy();
    expect(screen.getByText('bad entry')).toBeTruthy();
  });

  it('shows a refused read', async () => {
    stubControlPlane({
      'GET /api/v1/capabilities': caps(),
      // 400, not 503: the SDK retries 5xx with backoff (retryableStatuses).
      [OP]: refused(400, 'caller policy not configured'),
    });
    render(withControlPlane(<CallerPolicyPage />));

    const card = await screen.findByTestId('caller-policy-error');
    expect(card.textContent).toContain('caller policy not configured');
  });

  it('makes no read the server does not offer', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/capabilities': caps(true),
      [OP]: ok({ strategy: 'allowlist', identities: [], list_valid: true, anchors_configured: false, attested_peers_available: false, admits_nobody: false }),
    });
    render(withControlPlane(<CallerPolicyPage />));

    expect((await screen.findByTestId('caller-policy-not-enabled')).textContent).toContain('not-configured: attestation');
    expect(count(sent, 'GET', '/api/v1/attestation/callers')).toBe(0);
    const button = screen.getByRole('button', { name: 'Refresh' }) as HTMLButtonElement;
    await waitFor(() => expect(button.disabled).toBe(true));
    expect(button.getAttribute('title')).toBe('not-configured: attestation');
    expect(button.getAttribute('data-capability-op')).toBe(OP);
  });
});
