'use client';

/**
 * vTPM templates and bundles hook (#1674, UI epic #1665 slice 34).
 *
 * The SDK's declared vTPM response types (types/vtpm.ts) differ from the
 * flat snake_case payloads the REST handlers emit (gap #445). Until the SDK
 * is aligned, every result is converted here, once, to the wire shapes
 * below, and the pages use only these wire types.
 */

import type { ApiResponse } from 'trusted-platform-sdk';
import { useVTPM, useApi, useMutation } from '@/hooks';
import { useToast } from '@/hooks/use-toast';

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

  const bundles = useApi(
    async () =>
      wire<{ bundles?: VTPMBundleWire[]; total?: number }>(
        await vtpm.listBundles({ options: { limit: 100 } })
      ),
    [],
    { onError }
  );

  const createTemplate = useMutation(
    async (input: CreateTemplateInput) =>
      // Kept in the SDK's request shape so it compiles before and after #1590.
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
    async (archive: Blob) => wire<VTPMBundleWire>(await vtpm.importBundle(archive)),
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
