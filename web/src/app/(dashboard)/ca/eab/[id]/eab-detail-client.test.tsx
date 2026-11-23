import type { ReactNode } from 'react';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { GetEnrollmentURLResponse } from 'trusted-platform-sdk';

import EABCredentialDetailClient from './eab-detail-client';

// The enrollment URL response on the wire is { url, timestamp } (timestamp =
// time of generation); it carries no expiry. The URL embeds the credential,
// so the Enrollment URL card shows the credential's own expiry.

const { getURL } = vi.hoisted(() => ({ getURL: vi.fn() }));
const caps = vi.hoisted(() => ({ capability: vi.fn() }));
const api = vi.hoisted(() => ({ useApi: vi.fn() }));

vi.mock('next/link', () => ({
  default: ({ href, children }: { href: string; children: ReactNode }) => (
    <a href={href}>{children}</a>
  ),
}));

vi.mock('next/navigation', () => ({
  useParams: () => ({ id: '1700000000000000001' }),
  usePathname: () => '/ca/eab/1700000000000000001',
}));

vi.mock('@/hooks', () => ({
  useEAB: () => ({
    service: { get: vi.fn() },
    getQRCode: { mutateAsync: vi.fn() },
    getEnrollmentURL: { mutateAsync: getURL },
    markUsed: { mutateAsync: vi.fn() },
  }),
  useApi: (...args: unknown[]) => api.useApi(...args),
}));

vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({ loading: false, error: undefined, capability: caps.capability }),
}));

beforeEach(() => {
  api.useApi.mockReset();
  api.useApi.mockImplementation(() => ({
    data: {
      credential: {
        id: '1700000000000000001',
        keyId: 'kid-1',
        hmacKey: 'x',
        profileId: '1',
        tenantId: 't1',
        expiresAt: '2026-12-31T00:00:00Z',
        status: 'EAB_CREDENTIAL_STATUS_ACTIVE',
        createdAt: '2026-11-01T00:00:00Z',
      },
    },
    error: null,
    refetch: vi.fn(),
  }));
  caps.capability.mockReset();
  caps.capability.mockImplementation(() => ({ enabled: true }));
});

const READ_OP = 'GET /api/v1/eab/credentials/{id:[0-9]+}';
const QR_OP = 'GET /api/v1/eab/credentials/{id:[0-9]+}/qrcode';
const URL_OP = 'GET /api/v1/eab/credentials/{id:[0-9]+}/url';
const USED_OP = 'POST /api/v1/eab/credentials/{id:[0-9]+}/used';
const REASON = 'not-configured: eab';

function lastUseApiOptions(): { enabled?: boolean } {
  const calls = api.useApi.mock.calls;
  return calls[calls.length - 1][2] as { enabled?: boolean };
}

describe('EAB credential detail', () => {
  afterEach(() => {
    cleanup();
    getURL.mockReset();
  });

  it('shows the credential expiry beside the enrollment URL', async () => {
    const response: GetEnrollmentURLResponse = {
      url: 'https://acme.example/enroll?kid=kid-1',
      timestamp: '2026-11-20T12:00:00Z',
    };
    getURL.mockResolvedValue(response);

    render(<EABCredentialDetailClient />);
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Get Enrollment URL' }));
    });

    expect(screen.getByTestId('eab-enrollment-url').textContent).toBe(response.url);
    expect(screen.getByText('Expires 2026-12-31T00:00:00Z')).toBeTruthy();
    expect(screen.queryByText(/Expires undefined/)).toBeNull();
  });
});

describe('EAB credential detail capability gate', () => {
  afterEach(() => {
    cleanup();
    getURL.mockReset();
  });

  it('withholds Show QR Code, Get Enrollment URL and Mark Used when the server does not offer them', async () => {
    const off = new Set([QR_OP, URL_OP, USED_OP]);
    caps.capability.mockImplementation((op: string) =>
      off.has(op) ? { enabled: false, reason: REASON } : { enabled: true },
    );

    render(<EABCredentialDetailClient />);

    const controls: Array<[string, string]> = [
      ['Show QR Code', QR_OP],
      ['Get Enrollment URL', URL_OP],
      ['Mark Used', USED_OP],
    ];
    for (const [name, op] of controls) {
      const button = screen.getByRole('button', { name }) as HTMLButtonElement;
      expect(button.disabled).toBe(true);
      expect(button.getAttribute('title')).toBe(REASON);
      expect(button.getAttribute('data-capability-op')).toBe(op);
      expect(button.getAttribute('data-capability-enabled')).toBe('false');
    }

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Get Enrollment URL' }));
    });
    expect(getURL).not.toHaveBeenCalled();
  });

  it('makes no credential read the server does not offer', () => {
    caps.capability.mockImplementation((op: string) =>
      op === READ_OP ? { enabled: false, reason: REASON } : { enabled: true },
    );

    render(<EABCredentialDetailClient />);

    expect(lastUseApiOptions().enabled).toBe(false);
    expect(screen.getByTestId('eab-not-enabled').textContent).toContain(REASON);
    expect(screen.queryByRole('button', { name: 'Show QR Code' })).toBeNull();
  });

  it('reads the credential and leaves the controls on when the server offers them', () => {
    render(<EABCredentialDetailClient />);

    expect(lastUseApiOptions().enabled).toBe(true);
    for (const name of ['Show QR Code', 'Get Enrollment URL', 'Mark Used']) {
      expect(screen.getByRole('button', { name }).getAttribute('data-capability-enabled')).toBe('true');
    }
    expect((screen.getByRole('button', { name: 'Show QR Code' }) as HTMLButtonElement).disabled).toBe(false);
    expect((screen.getByRole('button', { name: 'Get Enrollment URL' }) as HTMLButtonElement).disabled).toBe(false);
  });
});
