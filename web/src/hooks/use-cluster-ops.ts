'use client';
import { useCallback, useEffect, useRef, useState } from 'react';
import { usePlatformCluster } from 'trusted-platform-sdk';
import type {
  ApiResponse,
  BootstrapClusterRequest,
  ClusterNode,
  ClusterOperationStatus,
  GetClusterStatusResponse,
} from 'trusted-platform-sdk';

/**
 * Drives ClusterService GetStatus, ListNodes, Bootstrap, Join and Leave for
 * the cluster page (#2043).
 */
export interface JoinClusterForm {
  nodeName?: string;
  /** Comma- or whitespace-separated host:port list. */
  seedAddresses: string;
}

export interface LeaveClusterForm {
  nodeId?: string;
  force?: boolean;
}

export interface UseClusterOpsResult {
  status: GetClusterStatusResponse | null;
  nodes: ClusterNode[];
  /** False when the server reports no cluster service (503 and the like). */
  available: boolean;
  unavailableReason: string | null;
  loading: boolean;
  busy: boolean;
  error: string | null;
  notice: string | null;
  refresh: () => Promise<void>;
  bootstrap: (request: BootstrapClusterRequest) => Promise<void>;
  join: (form: JoinClusterForm) => Promise<void>;
  leave: (form: LeaveClusterForm) => Promise<void>;
}

function unwrap<T>(response: ApiResponse<T>): T {
  if (!response.success || response.data === undefined) {
    throw new Error(response.error?.message ?? 'Request failed');
  }
  return response.data;
}

/** A write that answers HTTP 200 with status.success false failed. */
function checkStatus(status: ClusterOperationStatus | undefined, fallback: string): void {
  if (status && status.success === false) {
    throw new Error(status.message || fallback);
  }
}

// protojson emits enum names (NODE_ROLE_LEADER); the page shows the short name.
function shortNode(node: ClusterNode): ClusterNode {
  return {
    ...node,
    role: node.role ? String(node.role).replace(/^NODE_ROLE_/, '') : node.role,
    state: node.state ? String(node.state).replace(/^NODE_STATE_/, '') : node.state,
  };
}

function shortStatus(s: GetClusterStatusResponse): GetClusterStatusResponse {
  return {
    ...s,
    cluster: s.cluster
      ? { ...s.cluster, state: s.cluster.state ? String(s.cluster.state).replace(/^CLUSTER_STATE_/, '') : s.cluster.state }
      : s.cluster,
    localNode: s.localNode ? shortNode(s.localNode) : s.localNode,
    nodes: s.nodes?.map(shortNode),
  };
}

export function splitSeedAddresses(input: string): string[] {
  return input
    .split(/[\s,]+/)
    .map((a) => a.trim())
    .filter((a) => a.length > 0);
}

export function useClusterOps(): UseClusterOpsResult {
  const service = usePlatformCluster();
  const [status, setStatus] = useState<GetClusterStatusResponse | null>(null);
  const [nodes, setNodes] = useState<ClusterNode[]>([]);
  const [available, setAvailable] = useState(true);
  const [unavailableReason, setUnavailableReason] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const loadGen = useRef(0);

  const refresh = useCallback(async () => {
    const gen = ++loadGen.current;
    const current = () => gen === loadGen.current;
    setLoading(true);
    const [statusResp, nodesResp] = await Promise.all([
      service.getStatus().catch((err: unknown) => ({
        success: false,
        error: { code: 'NETWORK', message: err instanceof Error ? err.message : 'Request failed' },
      }) as ApiResponse<GetClusterStatusResponse>),
      service.listNodes().catch(() => ({ success: false }) as ApiResponse<{ nodes?: ClusterNode[] }>),
    ]);
    if (!current()) return;
    if (statusResp.success && statusResp.data) {
      setStatus(shortStatus(statusResp.data));
      setAvailable(true);
      setUnavailableReason(null);
    } else {
      setStatus(null);
      setAvailable(false);
      setUnavailableReason(statusResp.error?.message ?? 'Cluster service unavailable');
    }
    setNodes(nodesResp.success && nodesResp.data ? (nodesResp.data.nodes ?? []).map(shortNode) : []);
    setLoading(false);
  }, [service]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const run = useCallback(
    async (action: () => Promise<string>) => {
      setBusy(true);
      setError(null);
      setNotice(null);
      try {
        const message = await action();
        setNotice(message);
        await refresh();
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Request failed');
      } finally {
        setBusy(false);
      }
    },
    [refresh]
  );

  const bootstrap = useCallback(
    (request: BootstrapClusterRequest) =>
      run(async () => {
        const res = unwrap(await service.bootstrap(request));
        checkStatus(res.status, 'Bootstrap failed');
        const name = res.cluster?.name || request.clusterName;
        return name ? `Cluster ${name} bootstrapped` : 'Cluster bootstrapped';
      }),
    [run, service]
  );

  const join = useCallback(
    async (form: JoinClusterForm) => {
      const seedAddresses = splitSeedAddresses(form.seedAddresses);
      if (seedAddresses.length === 0) {
        setNotice(null);
        setError('Enter at least one seed address');
        return;
      }
      await run(async () => {
        const request = form.nodeName ? { nodeName: form.nodeName, seedAddresses } : { seedAddresses };
        const res = unwrap(await service.join(request));
        checkStatus(res.status, 'Join failed');
        return res.cluster?.name ? `Joined cluster ${res.cluster.name}` : 'Joined the cluster';
      });
    },
    [run, service]
  );

  const leave = useCallback(
    (form: LeaveClusterForm) =>
      run(async () => {
        const request: { nodeId?: string; force?: boolean } = {};
        if (form.nodeId) request.nodeId = form.nodeId;
        if (form.force) request.force = true;
        const res = unwrap(await service.leave(request));
        checkStatus(res.status, 'Leave failed');
        return form.nodeId ? `Node ${form.nodeId} left the cluster` : 'This node left the cluster';
      }),
    [run, service]
  );

  return { status, nodes, available, unavailableReason, loading, busy, error, notice, refresh, bootstrap, join, leave };
}
