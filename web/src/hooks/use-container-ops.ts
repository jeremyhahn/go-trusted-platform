'use client';

/**
 * Container detail operations (#1721): GetContainer, GetContainerMetrics,
 * ExecContainer and AttestContainer for one container, and the VM
 * attest-then-verify round trip (VerifyVMAttestation) for one VM.
 */

import { useCallback, useEffect, useState } from 'react';
import { useCompute } from 'trusted-platform-sdk';
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

export function useContainerOps(containerId: string): UseContainerOpsResult {
  const compute = useCompute();
  const [container, setContainer] = useState<Container | null>(null);
  const [metrics, setMetrics] = useState<ContainerMetrics | null>(null);
  // No id means nothing to load: start out of the loading state rather
  // than leaving it from inside the effect.
  const [loading, setLoading] = useState(Boolean(containerId));
  const [error, setError] = useState<string | null>(null);

  // The fetches set state only in promise callbacks, never synchronously
  // in the effect body (react-hooks/set-state-in-effect).
  const refresh = useCallback((): Promise<void> => {
    if (!containerId) return Promise.resolve();
    return compute
      .getContainer(containerId)
      .then((response) => {
        setContainer(unwrap(response, 'GetContainer').container);
        setError(null);
      })
      .catch((err: unknown) => {
        setError(err instanceof Error ? err.message : String(err));
      })
      .finally(() => {
        setLoading(false);
      });
  }, [compute, containerId]);

  const refreshMetrics = useCallback((): Promise<void> => {
    if (!containerId) return Promise.resolve();
    return compute
      .getContainerMetrics(containerId)
      .then((response) => {
        setMetrics(unwrap(response, 'GetContainerMetrics').metrics);
      })
      .catch(() => {
        setMetrics(null);
      });
  }, [compute, containerId]);

  useEffect(() => {
    if (!containerId) return;
    compute
      .getContainer(containerId)
      .then((response) => {
        setContainer(unwrap(response, 'GetContainer').container);
        setError(null);
      })
      .catch((err: unknown) => {
        setError(err instanceof Error ? err.message : String(err));
      })
      .finally(() => {
        setLoading(false);
      });
    compute
      .getContainerMetrics(containerId)
      .then((response) => {
        setMetrics(unwrap(response, 'GetContainerMetrics').metrics);
      })
      .catch(() => {
        setMetrics(null);
      });
  }, [compute, containerId]);

  const exec = useCallback(
    async (command: string[]) =>
      unwrap(await compute.execContainer({ id: containerId, command }), 'ExecContainer'),
    [compute, containerId]
  );

  const attest = useCallback(
    async () =>
      unwrap(
        await compute.attestContainer({ id: containerId, nonce: randomNonce() }),
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
