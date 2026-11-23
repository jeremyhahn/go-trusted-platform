'use client';

/**
 * useVMMigration moves one VM to another host through the control plane's
 * migration routes:
 *
 *   - MigrateVM:         POST /api/v1/compute/vms/{id}/migrate
 *   - PrepareMigration:  POST /api/v1/compute/migrations/prepare
 *   - FinalizeMigration: POST /api/v1/compute/migrations/{receiverId}/finalize
 *
 * MigrateVM goes through the SDK's ComputeService.migrateVM. PrepareMigration
 * and FinalizeMigration go on the SDK API client, because the SDK
 * ComputeService has no method for them yet; the receiver id is
 * path-encoded the same way the SDK encodes its own path segments.
 */

import { useMemo } from 'react';
import { usePlatformClient } from 'trusted-platform-sdk';

export interface MigrationStatus {
  success: boolean;
  message?: string;
}

/** Body of PrepareMigration: the destination readies a receiver for the VM. */
export interface PrepareMigrationBody {
  vmId: string;
  vmName: string;
  mode: 'cold' | 'live';
}

/** PrepareMigration's answer: where the source sends the VM. */
export interface PrepareMigrationResult {
  status?: MigrationStatus;
  receiverId: string;
  port: number;
  tlsHostname: string;
}

export interface FinalizeMigrationResult {
  status?: MigrationStatus;
}

export function useVMMigration(vmId: string) {
  const client = usePlatformClient();

  return useMemo(() => {
    const api = client.getApiClient();
    return {
      migrate: (destinationHost: string, liveMigration: boolean, bandwidthLimitMbps?: number) =>
        client.compute.migrateVM({ vmId, destinationHost, liveMigration, bandwidthLimitMbps }),
      prepare: (req: PrepareMigrationBody) =>
        api.post<PrepareMigrationResult>('/v1/compute/migrations/prepare', req),
      finalize: (receiverId: string, commit: boolean) =>
        api.post<FinalizeMigrationResult>(
          `/v1/compute/migrations/${encodeURIComponent(receiverId)}/finalize`,
          { commit }
        ),
    };
  }, [client, vmId]);
}
