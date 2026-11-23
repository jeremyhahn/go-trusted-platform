import * as React from 'react';
import { act, cleanup, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import KeyDetailPage from './key-detail-client';

// #2057: the key detail page lists the versions the KMS serves at
// GET /kms/keys/{name}/versions, instead of one version made up from the
// key record.

vi.mock('next/navigation', () => ({
  usePathname: () => '/kms/key-1',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

// The key controls are capability-gated; these cases need every op on.
vi.mock('@/hooks/use-capabilities', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/hooks/use-capabilities')>()),
  useCapabilities: () => ({ loading: false, error: undefined, capability: () => ({ enabled: true }) }),
}));

const KEY_PATH = 'GET /api/v1/kms/keys/key-1';
const VERSIONS_PATH = 'GET /api/v1/kms/keys/key-1/versions';

function routes(versions: Answer, keyVersion = 2): Record<string, Answer> {
  return {
    [KEY_PATH]: ok({
      key_id: 'key-1',
      name: 'payments',
      algorithm: 'AES_256_GCM',
      status: 'ENABLED',
      version: keyVersion,
      created_at: '2026-10-01T00:00:00Z',
    }),
    [VERSIONS_PATH]: versions,
  };
}

const servedVersions = ok({
  versions: [
    { version: 1, status: 'DISABLED', algorithm: 'AES_256_GCM', created_at: '2026-10-01T00:00:00Z' },
    { version: 2, status: 'ENABLED', algorithm: 'AES_256_GCM', created_at: '2026-11-01T00:00:00Z' },
  ],
});

async function renderPage() {
  const params = Promise.resolve({ id: 'key-1' });
  // The page reads its params with use(); await the act so the suspended
  // render resumes once the promise settles.
  await act(async () => {
    render(
      withControlPlane(
        <React.Suspense fallback={null}>
          <KeyDetailPage params={params} />
        </React.Suspense>
      )
    );
  });
  await screen.findByRole('heading', { level: 1, name: 'payments' });
}

describe('KeyDetailPage key versions', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('reads the versions through GET /kms/keys/{name}/versions', async () => {
    const sent = stubControlPlane(routes(servedVersions));
    await renderPage();

    await waitFor(() =>
      expect(sent).toContainEqual({ method: 'GET', path: '/api/v1/kms/keys/key-1/versions', body: undefined })
    );
  });

  it('lists every served version with its status and counts the rotations', async () => {
    stubControlPlane(routes(servedVersions));
    await renderPage();

    const first = await screen.findByRole('cell', { name: '1' });
    const second = screen.getByRole('cell', { name: '2' });
    expect(within(first.closest('tr')!).getByText('inactive')).toBeTruthy();
    expect(within(second.closest('tr')!).getByText('active')).toBeTruthy();
    expect(screen.getByText('Rotation Count').nextElementSibling?.textContent).toBe('1');
    expect(screen.queryByTestId('key-versions-partial')).toBeNull();
  });

  it('says so when the versions read is refused, and still shows the key', async () => {
    stubControlPlane(routes(refused(403, 'kms: permission denied')));
    await renderPage();

    expect(await screen.findByText('Key versions could not be read: kms: permission denied')).toBeTruthy();
    expect(screen.getByRole('heading', { level: 1, name: 'payments' })).toBeTruthy();
  });

  it('counts the rotations from the key version when the list stops short', async () => {
    const hundred = ok({
      versions: Array.from({ length: 100 }, (_, i) => ({
        version: i + 1,
        status: i === 99 ? 'ENABLED' : 'DISABLED',
        algorithm: 'AES_256_GCM',
        created_at: '2026-10-01T00:00:00Z',
      })),
    });
    stubControlPlane(routes(hundred, 101));
    await renderPage();

    await screen.findByRole('cell', { name: '100' });
    expect(screen.getByText('Rotation Count').nextElementSibling?.textContent).toBe('100');
    expect(screen.getByTestId('key-versions-partial').textContent).toBe('The KMS listed 100 of 101 versions.');
  });

  it('counts the rotations from the key version when the versions read is refused', async () => {
    stubControlPlane(routes(refused(403, 'kms: permission denied'), 3));
    await renderPage();

    await screen.findByText('Key versions could not be read: kms: permission denied');
    expect(screen.getByText('Rotation Count').nextElementSibling?.textContent).toBe('2');
    expect(screen.queryByTestId('key-versions-partial')).toBeNull();
  });
});
