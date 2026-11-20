'use client';

import * as React from 'react';
import { RegistryService, usePlatformClient } from 'trusted-platform-sdk';
import type { ApiResponse, RegistryArtifactDetail } from 'trusted-platform-sdk';

export type { RegistryArtifactDetail };

/** Registry health, as the daemon's RegistryHealthStatus enum. */
export type RegistryHealthCode = 0 | 1 | 2 | 3;

export interface RegistryComponent {
  Name?: string;
  Status?: RegistryHealthCode;
  Message?: string;
}

/** GET /api/v1/compute/images/status (the Go struct, no json tags). */
export interface RegistryStatus {
  Health: RegistryHealthCode;
  Version?: string;
  ReadOnly?: boolean;
  Components?: RegistryComponent[] | null;
  StartedAt?: string;
  Timestamp?: string;
}

export interface RegistryTags {
  name: string;
  tags: string[];
}

export interface UseRegistryResult {
  status: RegistryStatus | null;
  statusError: string | null;
  isStatusLoading: boolean;
  refetchStatus: () => Promise<void>;
  /** Tags of the last listed repository, null before the first list. */
  tags: RegistryTags | null;
  tagsError: string | null;
  isTagsLoading: boolean;
  listTags: (name: string) => Promise<void>;
  /** Delete a manifest by tag or digest; resolves once the tag list is reloaded. */
  deleteManifest: (name: string, reference: string) => Promise<void>;
  /** Detail of the last inspected tag, null before the first inspect. */
  inspection: RegistryArtifactDetail | null;
  inspectError: string | null;
  isInspecting: boolean;
  inspect: (name: string, tag: string) => Promise<void>;
}

/** Encode a repository name segment by segment, keeping its slashes. */
export function encodeRepository(name: string): string {
  return name.split('/').map(encodeURIComponent).join('/');
}

/** The data of a successful response, or the server's error thrown. */
function unwrap<T>(res: ApiResponse<T>): T | undefined {
  if (!res.success) {
    throw new Error(res.error?.message || 'request failed');
  }
  return res.data;
}

function message(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/**
 * useRegistry drives the container registry's Status, List, Inspect and
 * Delete operations through the SDK's RegistryService on the platform
 * client's API client (#2063): status and inspect on /v1/compute/images,
 * tags and manifests on the OCI distribution surface (/v2).
 */
export function useRegistry(): UseRegistryResult {
  const client = usePlatformClient();
  const registry = React.useMemo(() => new RegistryService(client.getApiClient()), [client]);

  const [status, setStatus] = React.useState<RegistryStatus | null>(null);
  const [statusError, setStatusError] = React.useState<string | null>(null);
  const [isStatusLoading, setStatusLoading] = React.useState(true);
  const [tags, setTags] = React.useState<RegistryTags | null>(null);
  const [tagsError, setTagsError] = React.useState<string | null>(null);
  const [isTagsLoading, setTagsLoading] = React.useState(false);
  const [inspection, setInspection] = React.useState<RegistryArtifactDetail | null>(null);
  const [inspectError, setInspectError] = React.useState<string | null>(null);
  const [isInspecting, setInspecting] = React.useState(false);

  const fetchStatus = React.useCallback(
    async () => (unwrap(await registry.getStatus()) ?? null) as RegistryStatus | null,
    [registry]
  );

  const refetchStatus = React.useCallback(async () => {
    setStatusLoading(true);
    setStatusError(null);
    try {
      setStatus(await fetchStatus());
    } catch (e: unknown) {
      setStatus(null);
      setStatusError(message(e));
    } finally {
      setStatusLoading(false);
    }
  }, [fetchStatus]);

  const listTags = React.useCallback(
    async (name: string) => {
      setTagsLoading(true);
      setTagsError(null);
      try {
        const body = unwrap(await registry.listTags(name));
        setTags({ name: body?.name ?? name, tags: body?.tags ?? [] });
      } catch (e: unknown) {
        setTags(null);
        setTagsError(message(e));
      } finally {
        setTagsLoading(false);
      }
    },
    [registry]
  );

  const inspect = React.useCallback(
    async (name: string, tag: string) => {
      setInspecting(true);
      setInspectError(null);
      try {
        setInspection(unwrap(await registry.inspect(name, tag)) ?? null);
      } catch (e: unknown) {
        setInspection(null);
        setInspectError(message(e));
      } finally {
        setInspecting(false);
      }
    },
    [registry]
  );

  const deleteManifest = React.useCallback(
    async (name: string, reference: string) => {
      unwrap(await registry.deleteManifest(name, reference));
      await listTags(name);
    },
    [registry, listTags]
  );

  React.useEffect(() => {
    let live = true;
    fetchStatus()
      .then(
        (data) => {
          if (live) setStatus(data);
        },
        (e: unknown) => {
          if (live) setStatusError(message(e));
        }
      )
      .finally(() => {
        if (live) setStatusLoading(false);
      });
    return () => {
      live = false;
    };
  }, [fetchStatus]);

  return {
    status,
    statusError,
    isStatusLoading,
    refetchStatus,
    tags,
    tagsError,
    isTagsLoading,
    listTags,
    deleteManifest,
    inspection,
    inspectError,
    isInspecting,
    inspect,
  };
}
