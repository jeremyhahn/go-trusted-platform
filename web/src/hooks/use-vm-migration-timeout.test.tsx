import { act, cleanup, renderHook } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

const fakeClient = vi.hoisted(() => ({
  compute: {
    migrateVM: vi.fn().mockResolvedValue({ success: true }),
    prepareMigration: vi.fn(),
    finalizeMigration: vi.fn(),
  },
}));

vi.mock('trusted-platform-sdk', async (importOriginal) => ({
  ...(await importOriginal<typeof import('trusted-platform-sdk')>()),
  usePlatformClient: () => fakeClient,
}));

import * as migration from './use-vm-migration';

afterEach(() => {
  cleanup();
});

describe('useVMMigration request options', () => {
  it('waits the 2-hour migration window and never retries MigrateVM', async () => {
    // Read through the namespace so a missing export fails as an assertion.
    const windowMs = (migration as Record<string, unknown>).MIGRATE_REQUEST_TIMEOUT_MS;
    expect(windowMs).toBe(2 * 60 * 60 * 1000);

    const { result } = renderHook(() => migration.useVMMigration('vm-1'));
    await act(async () => {
      await result.current.migrate('destination.example.test', true);
    });

    expect(fakeClient.compute.migrateVM).toHaveBeenCalledWith(
      { vmId: 'vm-1', destinationHost: 'destination.example.test', liveMigration: true, bandwidthLimitMbps: undefined },
      { timeout: windowMs, retry: { enabled: false } }
    );
  });
});
