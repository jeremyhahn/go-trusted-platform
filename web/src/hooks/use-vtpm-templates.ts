'use client';

/**
 * vTPM templates and bundles hook (#1674, UI epic #1665 slice 34).
 *
 * The SDK's declared vTPM response types (types/vtpm.ts) differ from the
 * flat snake_case payloads the REST handlers emit (gap #445). Until the SDK
 * is aligned, every result is converted here, once, to the wire shapes
 * below, and the pages use only these wire types.
 */

import type { ApiResponse, VTPMService } from 'trusted-platform-sdk';
import { useVTPM, useApi, useMutation } from '@/hooks';
import { useToast } from '@/hooks/use-toast';
import { useState } from 'react';

/** Bundles fetched per page of the bundle list (the REST handler pages by limit and offset). */
export const VTPM_BUNDLE_PAGE_SIZE = 100;

export interface VTPMTemplateWire {
  id: string;
  description?: string;
  tpm_state_dir: string;
  nvram_path: string;
  secure_boot_keys_dir?: string;
  ek_algorithm: string;
  secure_boot_enabled: boolean;
  created_at?: string;
}

export interface VTPMBundleManifestWire {
  version: string;
  id: string;
  mode: string;
  hostname?: string;
  created_at?: string;
  ek_algorithm: string;
  ek_handle: number;
  secure_boot_enabled: boolean;
  labels?: Record<string, string>;
  cloned_from?: string;
}

export interface VTPMBundleWire {
  id: string;
  mode: string;
  manifest?: VTPMBundleManifestWire;
  tpm_state?: { state_dir: string; permall_file: string };
  ovmf_state?: { nvram_file: string };
  created_at?: string;
  cloned_from?: string;
}

export interface VTPMValidationWire {
  valid: boolean;
  errors?: string[];
}

export interface VTPMPathWire {
  path: string;
}

export interface CreateTemplateInput {
  id: string;
  description?: string;
  ekAlgorithm: 'RSA' | 'ECC';
  secureBootEnabled: boolean;
}

export interface CloneTemplateInput {
  templateId: string;
  hostname: string;
}

/** Converts an SDK response to its wire shape (#445). */
function wire<T>(response: unknown): ApiResponse<T> {
  return response as unknown as ApiResponse<T>;
}

/** The camelCase bundle VTPMService.importBundle resolves with. */
export type VTPMBundle = NonNullable<Awaited<ReturnType<VTPMService['importBundle']>>['data']>;

/**
 * bundleToWire maps the SDK's camelCase VTPMBundle onto the snake_case wire
 * shape the bundle views read, so an imported bundle keeps its fields.
 */
export function bundleToWire(b: VTPMBundle): VTPMBundleWire {
  const m = b.manifest;
  return {
    id: b.id,
    mode: String(b.mode),
    ...(m !== undefined && {
      manifest: {
        version: m.version,
        id: m.id,
        mode: String(m.mode),
        hostname: m.hostname,
        created_at: m.createdAt,
        ek_algorithm: String(m.ekAlgorithm),
        ek_handle: m.ekHandle,
        secure_boot_enabled: m.secureBootEnabled,
        ...(m.labels !== undefined && { labels: m.labels }),
        ...(m.clonedFrom !== undefined && { cloned_from: m.clonedFrom }),
      },
    }),
    ...(b.tpmState !== undefined && {
      tpm_state: { state_dir: b.tpmState.stateDir, permall_file: b.tpmState.permallFile },
    }),
    ...(b.ovmfState !== undefined && { ovmf_state: { nvram_file: b.ovmfState.nvramFile } }),
    created_at: b.createdAt,
    ...(b.clonedFrom !== undefined && { cloned_from: b.clonedFrom }),
  };
}

export function useVTPMTemplates() {
  const vtpm = useVTPM();
  const { toast } = useToast();

  const onError = (error: { message?: string }) => {
    toast({
      title: 'Error',
      description: error.message || 'vTPM request failed',
      variant: 'destructive',
    });
  };

  const templates = useApi(
    async () => wire<{ templates?: VTPMTemplateWire[] }>(await vtpm.listTemplates()),
    [],
    { onError }
  );

  const [bundleOffset, setBundleOffset] = useState(0);
  const bundles = useApi(
    async () =>
      wire<{ bundles?: VTPMBundleWire[]; total?: number }>(
        await vtpm.listBundles({
          options: { limit: VTPM_BUNDLE_PAGE_SIZE, offset: bundleOffset },
        })
      ),
    [bundleOffset],
    { onError }
  );

  const createTemplate = useMutation(
    async (input: CreateTemplateInput) =>
      wire<VTPMTemplateWire>(
        await vtpm.createTemplate({
          options: {
            id: input.id,
            description: input.description,
            ekAlgorithm: input.ekAlgorithm,
            secureBootEnabled: input.secureBootEnabled,
          },
        })
      ),
    { onSuccess: () => void templates.refetch(), onError }
  );

  const getTemplate = useMutation(
    async (id: string) => wire<VTPMTemplateWire>(await vtpm.getTemplate(id)),
    { onError }
  );

  const cloneTemplate = useMutation(
    async (input: CloneTemplateInput) =>
      wire<VTPMBundleWire>(
        await vtpm.cloneTemplate({
          options: { templateId: input.templateId, hostname: input.hostname },
        })
      ),
    { onSuccess: () => void bundles.refetch(), onError }
  );

  const deleteTemplate = useMutation(
    async (id: string) =>
      wire<{ success: boolean; message?: string }>(await vtpm.deleteTemplate(id)),
    { onSuccess: () => void templates.refetch(), onError }
  );

  const importBundle = useMutation(
    async (archive: Blob): Promise<ApiResponse<VTPMBundleWire>> => {
      // importBundle already resolves with a camelCase VTPMBundle: convert it,
      // a cast would leave every snake_case field undefined.
      const response = await vtpm.importBundle(archive);
      return { ...response, data: response.data ? bundleToWire(response.data) : undefined };
    },
    { onSuccess: () => void bundles.refetch(), onError }
  );

  const getBundle = useMutation(
    async (id: string) => wire<VTPMBundleWire>(await vtpm.getBundle(id)),
    { onError }
  );

  const validateBundle = useMutation(
    async (id: string) => wire<VTPMValidationWire>(await vtpm.validateBundle(id)),
    { onError }
  );

  const getBundlePath = useMutation(
    async (id: string) => wire<VTPMPathWire>(await vtpm.getBundlePath(id)),
    { onError }
  );

  const getTPMSocketPath = useMutation(
    async (id: string) => wire<VTPMPathWire>(await vtpm.getTPMSocketPath(id)),
    { onError }
  );

  const getNVRAMPath = useMutation(
    async (id: string) => wire<VTPMPathWire>(await vtpm.getNVRAMPath(id)),
    { onError }
  );

  return {
    templates: templates.data?.templates ?? [],
    templatesLoading: templates.isLoading,
    refetchTemplates: templates.refetch,
    bundles: bundles.data?.bundles ?? [],
    bundlesLoading: bundles.isLoading,
    refetchBundles: bundles.refetch,
    bundleOffset,
    hasNextBundlePage: (bundles.data?.bundles?.length ?? 0) === VTPM_BUNDLE_PAGE_SIZE,
    nextBundlePage: () => setBundleOffset((o) => o + VTPM_BUNDLE_PAGE_SIZE),
    prevBundlePage: () => setBundleOffset((o) => Math.max(0, o - VTPM_BUNDLE_PAGE_SIZE)),
    createTemplate,
    getTemplate,
    cloneTemplate,
    deleteTemplate,
    importBundle,
    getBundle,
    validateBundle,
    getBundlePath,
    getTPMSocketPath,
    getNVRAMPath,
  };
}
