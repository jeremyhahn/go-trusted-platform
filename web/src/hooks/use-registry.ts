'use client';

import * as React from 'react';

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

const fetchOpts: RequestInit = {
  credentials: 'include',
  headers: { Accept: 'application/json' },
};

async function failure(res: Response): Promise<Error> {
  const text = await res.text().catch(() => '');
  return new Error(text ? `HTTP ${res.status}: ${text}` : `HTTP ${res.status}`);
}

async function fetchStatus(): Promise<RegistryStatus> {
  const res = await fetch('/api/v1/compute/images/status', fetchOpts);
  if (!res.ok) {
    throw await failure(res);
  }
  const body = await res.json();
  return (body && typeof body.payload === 'object' && body.payload !== null
    ? body.payload
    : body) as RegistryStatus;
}

/**
 * useRegistry reads the container registry: its status from the daemon's
 * REST surface and tags and manifests from the OCI distribution surface
 * (/v2). The SDK's RegistryService covers the same calls; the fetch is
 * direct, as on the images page, so session cookies ride along.
 */
export function useRegistry(): UseRegistryResult {
  const [status, setStatus] = React.useState<RegistryStatus | null>(null);
  const [statusError, setStatusError] = React.useState<string | null>(null);
  const [isStatusLoading, setStatusLoading] = React.useState(true);
  const [tags, setTags] = React.useState<RegistryTags | null>(null);
  const [tagsError, setTagsError] = React.useState<string | null>(null);
  const [isTagsLoading, setTagsLoading] = React.useState(false);

  const refetchStatus = React.useCallback(async () => {
    setStatusLoading(true);
    setStatusError(null);
    try {
      setStatus(await fetchStatus());
    } catch (e: unknown) {
      setStatusError(e instanceof Error ? e.message : String(e));
    } finally {
      setStatusLoading(false);
    }
  }, []);

  const listTags = React.useCallback(async (name: string) => {
    setTagsLoading(true);
    setTagsError(null);
    try {
      const res = await fetch(`/v2/${encodeRepository(name)}/tags/list`, fetchOpts);
      if (!res.ok) {
        throw await failure(res);
      }
      const body = (await res.json()) as Partial<RegistryTags>;
      setTags({ name: body.name ?? name, tags: body.tags ?? [] });
    } catch (e: unknown) {
      setTags(null);
      setTagsError(e instanceof Error ? e.message : String(e));
    } finally {
      setTagsLoading(false);
    }
  }, []);

  const deleteManifest = React.useCallback(
    async (name: string, reference: string) => {
      const res = await fetch(
        `/v2/${encodeRepository(name)}/manifests/${encodeURIComponent(reference)}`,
        { ...fetchOpts, method: 'DELETE' }
      );
      if (!res.ok) {
        throw await failure(res);
      }
      await listTags(name);
    },
    [listTags]
  );

  React.useEffect(() => {
    let live = true;
    fetchStatus()
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
  }, []);

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
