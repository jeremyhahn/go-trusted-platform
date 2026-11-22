'use client';

import * as React from 'react';
import { RegistryService, usePlatformClient } from 'trusted-platform-sdk';

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
}

/** Encode a repository name segment by segment, keeping its slashes. */
export function encodeRepository(name: string): string {
  return name.split('/').map(encodeURIComponent).join('/');
}

/** apiFailure turns an SDK refusal into the hook's Error, keeping the HTTP status. */
function apiFailure(error: { status?: number; message: string }): Error {
  return new Error(error.status !== undefined ? `HTTP ${error.status}: ${error.message}` : error.message);
}

/**
 * useRegistry reads the container registry through the SDK RegistryService:
 * its status from the daemon's REST surface, and tags and manifest deletes
 * from the OCI distribution surface (/v2) at the host root (rootRelative).
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

  const readStatus = React.useCallback(async (): Promise<RegistryStatus> => {
    const res = await registry.getStatus();
    if (res.error) {
      throw apiFailure(res.error);
    }
    const data = res.data;
    if (!data) {
      throw new Error('registry status: empty response');
    }
    return {
      Health: data.Health as number as RegistryHealthCode,
      Version: data.Version,
      ReadOnly: data.ReadOnly,
      Components: data.Components as RegistryComponent[] | null | undefined,
      StartedAt: data.StartedAt,
      Timestamp: data.Timestamp,
    };
  }, [registry]);

  const refetchStatus = React.useCallback(async () => {
    setStatusLoading(true);
    setStatusError(null);
    try {
      setStatus(await readStatus());
    } catch (e: unknown) {
      setStatusError(e instanceof Error ? e.message : String(e));
    } finally {
      setStatusLoading(false);
    }
  }, [readStatus]);

  const listTags = React.useCallback(
    async (name: string) => {
      setTagsLoading(true);
      setTagsError(null);
      try {
        const res = await registry.listTags(name);
        if (res.error) {
          setTags(null);
          setTagsError(apiFailure(res.error).message);
          return;
        }
        setTags({ name: res.data?.name ?? name, tags: res.data?.tags ?? [] });
      } catch (e: unknown) {
        setTags(null);
        setTagsError(e instanceof Error ? e.message : String(e));
      } finally {
        setTagsLoading(false);
      }
    },
    [registry]
  );

  const deleteManifest = React.useCallback(
    async (name: string, reference: string) => {
      const res = await registry.deleteManifest(name, reference);
      if (res.error) {
        throw apiFailure(res.error);
      }
      await listTags(name);
    },
    [registry, listTags]
  );

  React.useEffect(() => {
    let live = true;
    readStatus()
      .then(
        (data) => {
          if (live) setStatus(data);
        },
        (e: unknown) => {
          if (live) setStatusError(e instanceof Error ? e.message : String(e));
        }
      )
      .finally(() => {
        if (live) setStatusLoading(false);
      });
    return () => {
      live = false;
    };
  }, [readStatus]);

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
  };
}
