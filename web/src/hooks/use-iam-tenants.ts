"use client";

import { useCallback } from "react";
import { useIAM, useApi } from "trusted-platform-sdk";
import type {
  ApiResponse,
  CreateIAMTenantRequest,
  DeleteIAMTenantResponse,
  IAMTenant,
  IAMTenantResponse,
  UpdateIAMTenantRequest,
} from "trusted-platform-sdk";

/**
 * Tenant administration over the IAM REST routes: GET/POST /tenants and
 * GET/PUT/DELETE /tenants/{tenant} (system scope, #1744).
 */
export interface UseIAMTenantsResult {
  tenants: IAMTenant[];
  isLoading: boolean;
  error: Error | undefined;
  refetch: () => void;
  getTenant: (tenantId: string) => Promise<ApiResponse<IAMTenantResponse>>;
  createTenant: (request: CreateIAMTenantRequest) => Promise<ApiResponse<IAMTenantResponse>>;
  updateTenant: (request: UpdateIAMTenantRequest) => Promise<ApiResponse<IAMTenantResponse>>;
  deleteTenant: (tenantId: string) => Promise<ApiResponse<DeleteIAMTenantResponse>>;
}

export function useIAMTenants(): UseIAMTenantsResult {
  const iam = useIAM();
  const { data, isLoading, error, refetch } = useApi(() => iam.listTenants(), [iam]);

  const getTenant = useCallback((tenantId: string) => iam.getTenant(tenantId), [iam]);
  const createTenant = useCallback(
    (request: CreateIAMTenantRequest) => iam.createTenant(request),
    [iam],
  );
  const updateTenant = useCallback(
    (request: UpdateIAMTenantRequest) => iam.updateTenant(request),
    [iam],
  );
  const deleteTenant = useCallback((tenantId: string) => iam.deleteTenant(tenantId), [iam]);

  return {
    tenants: data?.tenants ?? [],
    isLoading,
    error,
    refetch: () => {
      void refetch();
    },
    getTenant,
    createTenant,
    updateTenant,
    deleteTenant,
  };
}
