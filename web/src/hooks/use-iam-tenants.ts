"use client";

import { useCallback, useEffect, useState } from "react";
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
 * The SDK client leaves throwOnError false, so an HTTP error resolves to
 * { success: false, error } instead of rejecting. Turn it into a thrown
 * Error so callers' catch paths run (#1757).
 */
export function expectOk<T>(response: ApiResponse<T>, operation: string): ApiResponse<T> {
  if (response.error || response.success === false) {
    throw new Error(response.error?.message || `${operation} failed`);
  }
  return response;
}

/** Tenants per page; the REST handler's default limit is also 50. */
export const TENANTS_PAGE_SIZE = 50;

/** Number of tenant pages for a server total, at least one. */
export function tenantPageCount(total: number | undefined, pageSize: number): number {
  if (!total || total <= 0 || pageSize <= 0) return 1;
  return Math.ceil(total / pageSize);
}

/**
 * Tenant administration over the IAM REST routes: GET/POST /tenants and
 * GET/PUT/DELETE /tenants/{tenant} (system scope, #1744).
 */
export interface UseIAMTenantsResult {
  tenants: IAMTenant[];
  /** Tenants on the server, across every page. */
  total: number;
  /** Current page, 1-indexed. */
  page: number;
  pageCount: number;
  setPage: (page: number) => void;
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
  const [page, setPage] = useState(1);
  const { data, isLoading, error, refetch } = useApi(
    () => iam.listTenants({ page, pageSize: TENANTS_PAGE_SIZE }),
    [iam, page],
  );
  const total = data?.total ?? 0;
  const pageCount = tenantPageCount(total, TENANTS_PAGE_SIZE);
  // A delete can empty the last page: step back to the new last page.
  useEffect(() => {
    if (data && page > pageCount) setPage(pageCount);
  }, [data, page, pageCount]);

  const getTenant = useCallback(
    async (tenantId: string) => expectOk(await iam.getTenant(tenantId), "Get tenant"),
    [iam],
  );
  const createTenant = useCallback(
    async (request: CreateIAMTenantRequest) => expectOk(await iam.createTenant(request), "Create tenant"),
    [iam],
  );
  const updateTenant = useCallback(
    async (request: UpdateIAMTenantRequest) => expectOk(await iam.updateTenant(request), "Update tenant"),
    [iam],
  );
  const deleteTenant = useCallback(
    async (tenantId: string) => expectOk(await iam.deleteTenant(tenantId), "Delete tenant"),
    [iam],
  );

  return {
    tenants: data?.tenants ?? [],
    total,
    page,
    pageCount,
    setPage,
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
