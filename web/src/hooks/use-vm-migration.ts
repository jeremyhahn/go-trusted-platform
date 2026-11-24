'use client';

/**
 * useVMMigration moves one VM to another host through the control plane's
 * migration routes:
 *
 *   - MigrateVM:         POST /api/v1/compute/vms/{id}/migrate
 *   - PrepareMigration:  POST /api/v1/compute/migrations/prepare
 *   - FinalizeMigration: POST /api/v1/compute/migrations/{receiverId}/finalize
 *
 * All three go through the SDK's ComputeService (migrateVM, prepareMigration
 * and finalizeMigration), which path-encodes the VM and receiver ids.
 *
 * MigrateVM is sent with a 2-hour timeout (MIGRATE_REQUEST_TIMEOUT_MS) and
 * retry off, instead of the client's 30 s default and its retries.
 */

import { useMemo } from 'react';
import { usePlatformClient } from 'trusted-platform-sdk';

export interface MigrationStatus {
  success: boolean;
  message?: string;
}

/**
 * The guest spec the receiver builds the incoming VM from: the fields of the
 * SDK's VMMigrationSpec (which its index does not export), with memory and
 * vCPUs required. PrepareMigration refuses a request without a spec.
 */
export interface MigrationGuestSpec {
  memoryMb: number;
  cpus: number;
  diskSize?: string;
  bootMode?: string;
  secureBoot?: boolean;
  enableKvm?: boolean;
  tpmEnabled?: boolean;
  networkMode?: string;
  macAddress?: string;
  /** "x86_64" | "aarch64"; empty means x86_64. */
  arch?: string;
}

/** Body of PrepareMigration: the destination readies a receiver for the VM. */
export interface PrepareMigrationBody {
  vmId: string;
  vmName: string;
  mode: 'cold' | 'live';
  spec: MigrationGuestSpec;
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

/**
 * How long MigrateVM may take. A migration copies the guest's memory and
 * disks to the destination, and the server keeps the reply open for the same
 * window; a retry would start a second migration, so MigrateVM is never
 * retried.
 */
export const MIGRATE_REQUEST_TIMEOUT_MS = 2 * 60 * 60 * 1000;

export function useVMMigration(vmId: string) {
  const client = usePlatformClient();

  return useMemo(() => {
    return {
      migrate: (destinationHost: string, liveMigration: boolean, bandwidthLimitMbps?: number) =>
        client.compute.migrateVM(
          { vmId, destinationHost, liveMigration, bandwidthLimitMbps },
          { timeout: MIGRATE_REQUEST_TIMEOUT_MS, retry: { enabled: false } }
        ),
      prepare: (req: PrepareMigrationBody) => client.compute.prepareMigration(req),
      finalize: (receiverId: string, commit: boolean) =>
        client.compute.finalizeMigration({ receiverId, commit }),
    };
  }, [client, vmId]);
}
