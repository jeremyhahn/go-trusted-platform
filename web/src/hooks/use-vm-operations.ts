"use client";

/**
 * VM operations for the VM detail and migration pages (#1727).
 *
 * Each operation calls the compute service, toasts the outcome and returns
 * the response data (undefined on failure), so a page can show the result.
 */

import { useCallback, useState } from "react";
import { useCompute } from "trusted-platform-sdk";
import type {
  ApiResponse,
  AttestVMResponse,
  DiskConfig,
  FinalizeMigrationResponse,
  GetSnapshotResponse,
  PrepareMigrationRequest,
  PrepareMigrationResponse,
  VMMetricsResponse,
  CreateSnapshotResponse,
} from "trusted-platform-sdk";
import { useToast } from "./use-toast";

/** A random base64 nonce for an attestation request. */
// MigrateVM returns only after the transfer and finalization; the client default (providers.tsx) is 30 s.
export const MIGRATION_TIMEOUT_MS = 60 * 60 * 1000;

export function attestationNonce(): string {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  let s = "";
  bytes.forEach((b) => {
    s += String.fromCharCode(b);
  });
  return btoa(s);
}

export interface UseVMOperationsResult {
  /** Label of the operation in flight, or null */
  pending: string | null;
  suspend: (vmId: string) => Promise<boolean>;
  resume: (vmId: string) => Promise<boolean>;
  attest: (vmId: string) => Promise<AttestVMResponse | undefined>;
  metrics: (vmId: string) => Promise<VMMetricsResponse | undefined>;
  attachDisk: (vmId: string, disk: DiskConfig) => Promise<boolean>;
  detachDisk: (vmId: string, diskId: string) => Promise<boolean>;
  resizeDisk: (vmId: string, diskId: string, newSizeGb: number) => Promise<boolean>;
  createSnapshot: (vmId: string, name: string) => Promise<CreateSnapshotResponse | undefined>;
  getSnapshot: (vmId: string, snapshotId: string) => Promise<GetSnapshotResponse | undefined>;
  migrate: (vmId: string, destinationHost: string, liveMigration: boolean) => Promise<boolean>;
  prepareMigration: (request: PrepareMigrationRequest) => Promise<PrepareMigrationResponse | undefined>;
  finalizeMigration: (receiverId: string, commit: boolean) => Promise<FinalizeMigrationResponse | undefined>;
}

export function useVMOperations(): UseVMOperationsResult {
  const compute = useCompute();
  const { toast } = useToast();
  const [pending, setPending] = useState<string | null>(null);

  const run = useCallback(
    async <T,>(label: string, fn: () => Promise<ApiResponse<T>>): Promise<T | undefined> => {
      setPending(label);
      try {
        const response = await fn();
        if (response.success) {
          toast({ title: "Success", description: `${label} succeeded` });
          return response.data ?? ({} as T);
        }
        toast({
          title: "Error",
          description: `${label} failed: ${response.error?.message ?? "unknown error"}`,
          variant: "destructive",
        });
      } catch (error) {
        toast({
          title: "Error",
          description: `${label} failed: ${error instanceof Error ? error.message : "unknown error"}`,
          variant: "destructive",
        });
      } finally {
        setPending(null);
      }
      return undefined;
    },
    [toast]
  );

  const ok = async <T,>(p: Promise<T | undefined>) => (await p) !== undefined;

  return {
    pending,
    suspend: (vmId) => ok(run("Suspend", () => compute.suspendVM(vmId))),
    resume: (vmId) => ok(run("Resume", () => compute.resumeVM(vmId))),
    attest: (vmId) =>
      run("Attest", () => compute.attestVM({ vmId, nonce: attestationNonce() })),
    metrics: (vmId) => run("Metrics", () => compute.getVMMetrics(vmId)),
    attachDisk: (vmId, disk) => ok(run("Attach disk", () => compute.attachDisk({ vmId, disk }))),
    detachDisk: (vmId, diskId) =>
      ok(run("Detach disk", () => compute.detachDisk({ vmId, diskId }))),
    resizeDisk: (vmId, diskId, newSizeGb) =>
      ok(run("Resize disk", () => compute.resizeDisk({ vmId, diskId, newSizeGb }))),
    createSnapshot: (vmId, name) =>
      run("Create snapshot", () => compute.createSnapshot({ vmId, config: { name } })),
    getSnapshot: (vmId, snapshotId) =>
      run("Get snapshot", () => compute.getSnapshot(vmId, snapshotId)),
    migrate: (vmId, destinationHost, liveMigration) =>
      ok(run("Migrate", () => compute.migrateVM({ vmId, destinationHost, liveMigration }, { timeoutMs: MIGRATION_TIMEOUT_MS }))),
    prepareMigration: (request) => run("Prepare migration", () => compute.prepareMigration(request)),
    finalizeMigration: (receiverId, commit) =>
      run("Finalize migration", () => compute.finalizeMigration({ receiverId, commit })),
  };
}
