import type { ReactNode } from 'react';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { GetEnrollmentURLResponse } from 'trusted-platform-sdk';

import EABCredentialDetailClient from './eab-detail-client';

// The enrollment URL response on the wire is { url, timestamp } (timestamp =
// time of generation); it carries no expiry. The URL embeds the credential,
// so the Enrollment URL card shows the credential's own expiry.

const { getURL } = vi.hoisted(() => ({ getURL: vi.fn() }));

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
  useApi: () => ({
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
  }),
}));

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
    expect(screen.getByText('Generated 2026-11-20T12:00:00Z')).toBeTruthy();
  });
});
