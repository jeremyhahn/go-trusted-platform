'use client';

/**
 * Container detail operations (#1721): GetContainer, GetContainerMetrics,
 * ExecContainer and AttestContainer for one container, and the VM
 * attest-then-verify round trip (VerifyVMAttestation) for one VM.
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import { useCompute } from 'trusted-platform-sdk';
import { containerStatus } from '@/lib/compute-state';
import type {
  ApiResponse,
  AttestContainerResponse,
  Container,
  ContainerMetrics,
  ExecContainerResponse,
  VerifyVMAttestationResponse,
} from 'trusted-platform-sdk';

/** A fresh 32-byte nonce, base64-encoded. */
export function randomNonce(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let s = '';
  bytes.forEach((b) => {
    s += String.fromCharCode(b);
  });
  return btoa(s);
}

/** Decode base64 command output to text; returns the input when it is not base64. */
export function decodeOutput(b64?: string): string {
  if (!b64) return '';
  try {
    const bin = atob(b64);
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  } catch {
    return b64;
  }
}

/** Split a command line on whitespace into argv. */
export function splitCommand(line: string): string[] {
  const args: string[] = [];
  let current = '';
  let inArg = false;
  let quote: "'" | '"' | null = null;

  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (quote === "'") {
      if (ch === "'") quote = null;
      else current += ch;
    } else if (quote === '"') {
      if (ch === '"') {
        quote = null;
      } else if (ch === '\\' && (line[i + 1] === '"' || line[i + 1] === '\\')) {
        current += line[++i];
      } else {
        current += ch;
      }
    } else if (ch === "'" || ch === '"') {
      quote = ch;
      inArg = true;
    } else if (ch === '\\') {
      if (i + 1 < line.length) current += line[++i];
      inArg = true;
    } else if (/\s/.test(ch)) {
      if (inArg) {
        args.push(current);
        current = '';
        inArg = false;
      }
    } else {
      current += ch;
      inArg = true;
    }
  }

  if (quote) {
    throw new Error(`unterminated ${quote === "'" ? 'single' : 'double'} quote in command`);
  }
  if (inArg) args.push(current);
  return args;
}

function unwrap<T>(response: ApiResponse<T>, what: string): T {
  if (!response.success || !response.data) {
    const message = (response.error as { message?: string } | undefined)?.message;
    throw new Error(message || `${what} failed`);
  }
  return response.data;
}

export interface UseContainerOpsResult {
  container: Container | null;
  metrics: ContainerMetrics | null;
  loading: boolean;
  error: string | null;
  refresh: () => Promise<void>;
  refreshMetrics: () => Promise<void>;
  exec: (command: string[]) => Promise<ExecContainerResponse>;
  attest: () => Promise<AttestContainerResponse>;
}

/** A value tagged with the container ID it was read for. */
interface Tagged<T> {
  id: string;
  value: T;
}

function valueFor<T>(tagged: Tagged<T> | null, id: string, fallback: T): T {
  return tagged !== null && tagged.id === id ? tagged.value : fallback;
}

export function useContainerOps(containerId: string): UseContainerOpsResult {
  const compute = useCompute();
  // The container the hook is showing now. A response is kept only while
  // the ID it was requested for is still this one, so a delayed read of a
  // previous container (an effect, refresh() or refreshMetrics()) is dropped.
  const currentId = useRef(containerId);
  useEffect(() => {
    currentId.current = containerId;
  }, [containerId]);

  // State is tagged with its container ID, so a changed ID shows nothing
  // of the previous container while its own reads are in flight.
  const [containerState, setContainerState] = useState<Tagged<Container | null> | null>(null);
  const [metricsState, setMetricsState] = useState<Tagged<ContainerMetrics | null> | null>(null);
  const [errorState, setErrorState] = useState<Tagged<string | null> | null>(null);
  const [loadedId, setLoadedId] = useState<string | null>(null);

  // The fetches set state only in promise callbacks, never synchronously
  // in the effect body (react-hooks/set-state-in-effect).
  const fetchContainer = useCallback(
    (id: string): Promise<void> =>
      compute
        .getContainer(id)
        .then((response) => {
          const value = unwrap(response, 'GetContainer').container;
          if (currentId.current !== id) return;
          setContainerState({ id, value });
          setErrorState({ id, value: null });
        })
        .catch((err: unknown) => {
          if (currentId.current !== id) return;
          setErrorState({ id, value: err instanceof Error ? err.message : String(err) });
        })
        .finally(() => {
          if (currentId.current === id) setLoadedId(id);
        }),
    [compute]
  );

  const fetchMetrics = useCallback(
    (id: string): Promise<void> =>
      compute
        .getContainerMetrics(id)
        .then((response) => {
          const value = unwrap(response, 'GetContainerMetrics').metrics;
          if (currentId.current === id) setMetricsState({ id, value });
        })
        .catch(() => {
          if (currentId.current === id) setMetricsState({ id, value: null });
        }),
    [compute]
  );

  const refresh = useCallback((): Promise<void> => {
    if (!containerId) return Promise.resolve();
    return fetchContainer(containerId);
  }, [fetchContainer, containerId]);

  const refreshMetrics = useCallback((): Promise<void> => {
    if (!containerId) return Promise.resolve();
    return fetchMetrics(containerId);
  }, [fetchMetrics, containerId]);

  useEffect(() => {
    if (!containerId) return;
    void fetchContainer(containerId);
    void fetchMetrics(containerId);
  }, [fetchContainer, fetchMetrics, containerId]);

  const container = valueFor(containerState, containerId, null);
  const metrics = valueFor(metricsState, containerId, null);
  const error = valueFor(errorState, containerId, null);
  // No id means nothing to load.
  const loading = Boolean(containerId) && loadedId !== containerId;

  const exec = useCallback(
    async (command: string[]) =>
      unwrap(await compute.execContainer({ id: containerId, command }), 'ExecContainer'),
    [compute, containerId]
  );

  const attest = useCallback(
    async () =>
      unwrap(
        await compute.attestContainer({ id: containerId }),
        'AttestContainer'
      ),
    [compute, containerId]
  );

  return { container, metrics, loading, error, refresh, refreshMetrics, exec, attest };
}

/**
 * Attest a VM with a fresh nonce, then verify the quote it returned
 * (POST /vms/{id}/attest, then POST /vms/{id}/attest/verify).
 */
export function useVMAttestationVerify(vmId: string) {
  const compute = useCompute();
  return useCallback(async (): Promise<VerifyVMAttestationResponse> => {
    const nonce = randomNonce();
    const quote = unwrap(await compute.attestVM({ vmId, nonce }), 'AttestVM');
    return unwrap(
      await compute.verifyVMAttestation({
        vmId,
        nonce,
        quote: quote.quote ?? '',
        signature: quote.signature ?? '',
        signatureAlgorithm: quote.signatureAlgorithm ?? '',
      }),
      'VerifyVMAttestation'
    );
  }, [compute, vmId]);
}

/** Whether a control may be used, and why not when it may not. */
export interface ControlGate {
  enabled: boolean;
  reason: string | null;
}

const open: ControlGate = { enabled: true, reason: null };
const closed = (reason: string): ControlGate => ({ enabled: false, reason });

/**
 * Capability gates for the container detail controls (#2045): exec runs
 * only in a loaded, running container; attest needs a loaded container;
 * neither while another action is in flight.
 */
export function containerControlGates(
  container: Container | null,
  busy: boolean
): { exec: ControlGate; attest: ControlGate } {
  if (!container) {
    const gate = closed('Container not loaded');
    return { exec: gate, attest: gate };
  }
  if (busy) {
    const gate = closed('Another action is in progress');
    return { exec: gate, attest: gate };
  }
  const status = containerStatus(container.state);
  return {
    exec: status === 'running' ? open : closed(`Exec needs a running container (state: ${status})`),
    attest: open,
  };
}

/** Capability gate for the VM attest-then-verify control (#2045). */
export function vmVerifyGate(status: string | undefined, busy: boolean): ControlGate {
  if (busy) return closed('A verification is in progress');
  const state = (status || 'unknown').toLowerCase();
  return state === 'running'
    ? open
    : closed(`Attestation needs a running VM (state: ${state})`);
}
