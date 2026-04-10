/**
 * Generic API data fetching hook
 *
 * Provides a declarative way to fetch data from the API with automatic
 * state management for loading, error, and data states.
 *
 * @packageDocumentation
 */

import { useEffect, useState, useCallback, useRef } from 'react';
import type { ApiResponse } from '../../types/api.js';
import type { ApiError } from '../../errors/api-error.js';

/**
 * Options for the useApi hook
 *
 * @typeParam T - The type of data being fetched
 */
export interface UseApiOptions<T> {
  /**
   * Whether the query should be enabled.
   * When false, the fetcher will not be called.
   * @default true
   */
  enabled?: boolean;

  /**
   * Interval in milliseconds to automatically refetch data.
   * Set to 0 or undefined to disable polling.
   */
  refetchInterval?: number;

  /**
   * Callback fired when data is successfully fetched
   */
  onSuccess?: (data: T) => void;

  /**
   * Callback fired when an error occurs
   */
  onError?: (error: ApiError) => void;

  /**
   * Initial data to use before the first fetch completes.
   * Useful for SSR hydration.
   */
  initialData?: T;
}

/**
 * Result returned by the useApi hook
 *
 * @typeParam T - The type of data being fetched
 */
export interface UseApiResult<T> {
  /** The fetched data, or undefined if not yet fetched */
  data: T | undefined;

  /** The error if the fetch failed, or undefined if successful */
  error: ApiError | undefined;

  /** Whether the initial fetch is in progress */
  isLoading: boolean;

  /** Whether any fetch (initial or refetch) is in progress */
  isFetching: boolean;

  /** Whether an error occurred */
  isError: boolean;

  /** Whether data has been successfully fetched at least once */
  isSuccess: boolean;

  /** Manually trigger a refetch */
  refetch: () => Promise<void>;

  /**
   * Optimistically update data without refetching.
   * Useful for instant UI updates while waiting for server confirmation.
   */
  mutate: (data: T | ((prev: T | undefined) => T)) => void;
}

/**
 * Hook for fetching data from the API
 *
 * Provides automatic state management for loading, error, and data states
 * with support for polling, callbacks, and optimistic updates.
 *
 * @typeParam T - The type of data being fetched
 * @param fetcher - Function that returns a Promise of ApiResponse
 * @param deps - Dependencies array for the fetcher (like useEffect deps)
 * @param options - Configuration options
 * @returns Result object with data, error, and state information
 *
 * @example
 * ```tsx
 * // Basic usage
 * function CertificatesList() {
 *   const client = usePlatformClient();
 *   const { data, isLoading, error } = useApi(
 *     () => client.ca.listCertificates(),
 *     []
 *   );
 *
 *   if (isLoading) return <Loading />;
 *   if (error) return <Error message={error.message} />;
 *
 *   return (
 *     <ul>
 *       {data?.certificates.map(cert => (
 *         <li key={cert.serial}>{cert.subject}</li>
 *       ))}
 *     </ul>
 *   );
 * }
 *
 * // With polling
 * const { data } = useApi(
 *   () => client.platform.getHealth(),
 *   [],
 *   { refetchInterval: 5000 }
 * );
 *
 * // With conditional fetching
 * const { data } = useApi(
 *   () => client.ca.getCertificate(serial),
 *   [serial],
 *   { enabled: serial !== undefined }
 * );
 * ```
 */
export function useApi<T>(
  fetcher: () => Promise<ApiResponse<T>>,
  deps: unknown[],
  options?: UseApiOptions<T>
): UseApiResult<T> {
  const {
    enabled = true,
    refetchInterval,
    onSuccess,
    onError,
    initialData,
  } = options ?? {};

  const [data, setData] = useState<T | undefined>(initialData);
  const [error, setError] = useState<ApiError | undefined>(undefined);
  const [isLoading, setIsLoading] = useState<boolean>(enabled && initialData === undefined);
  const [isFetching, setIsFetching] = useState<boolean>(false);
  const [fetchCount, setFetchCount] = useState<number>(0);

  // Track deps changes with a stable reference
  const depsRef = useRef(deps);
  const depsChangedRef = useRef(0);

  // Check if deps have changed
  const depsChanged =
    deps.length !== depsRef.current.length ||
    deps.some((dep, i) => dep !== depsRef.current[i]);

  if (depsChanged) {
    depsRef.current = deps;
    depsChangedRef.current += 1;
  }

  // Use refs to avoid stale closures and unnecessary effect reruns
  const onSuccessRef = useRef(onSuccess);
  const onErrorRef = useRef(onError);
  const fetcherRef = useRef(fetcher);
  const isMountedRef = useRef(true);

  // Update refs when callbacks change
  useEffect(() => {
    onSuccessRef.current = onSuccess;
    onErrorRef.current = onError;
  }, [onSuccess, onError]);

  // Update fetcher ref when fetcher changes
  useEffect(() => {
    fetcherRef.current = fetcher;
  }, [fetcher]);

  // Track mount state
  useEffect(() => {
    isMountedRef.current = true;
    return () => {
      isMountedRef.current = false;
    };
  }, []);

  // Track if this is the first fetch
  const isFirstFetchRef = useRef(true);

  // Core fetch function
  const fetchData = useCallback(async () => {
    if (!enabled) {
      return;
    }

    setIsFetching(true);
    if (isFirstFetchRef.current) {
      setIsLoading(true);
    }
    setError(undefined);

    try {
      const response = await fetcherRef.current();

      // Only update state if component is still mounted
      if (!isMountedRef.current) {
        return;
      }

      if (response.error !== undefined) {
        const apiError = response.error as unknown as ApiError;
        setError(apiError);
        setIsLoading(false);
        setIsFetching(false);
        onErrorRef.current?.(apiError);
      } else if (response.data !== undefined) {
        setData(response.data);
        setError(undefined);
        setIsLoading(false);
        setIsFetching(false);
        isFirstFetchRef.current = false;
        setFetchCount((prev) => prev + 1);
        onSuccessRef.current?.(response.data);
      }
    } catch (err) {
      if (!isMountedRef.current) {
        return;
      }

      const apiError = err as ApiError;
      setError(apiError);
      setIsLoading(false);
      setIsFetching(false);
      onErrorRef.current?.(apiError);
    }
  }, [enabled]);

  // Initial fetch and refetch when deps change
  useEffect(() => {
    if (enabled) {
      void fetchData();
    }
  }, [enabled, fetchData, depsChangedRef.current]);

  // Polling interval
  useEffect(() => {
    if (!enabled || refetchInterval === undefined || refetchInterval <= 0) {
      return;
    }

    const intervalId = setInterval(() => {
      void fetchData();
    }, refetchInterval);

    return () => clearInterval(intervalId);
  }, [enabled, refetchInterval, fetchData]);

  // Manual refetch
  const refetch = useCallback(async () => {
    await fetchData();
  }, [fetchData]);

  // Optimistic update
  const mutate = useCallback((newData: T | ((prev: T | undefined) => T)) => {
    setData((prev) => {
      if (typeof newData === 'function') {
        return (newData as (prev: T | undefined) => T)(prev);
      }
      return newData;
    });
  }, []);

  return {
    data,
    error,
    isLoading,
    isFetching,
    isError: error !== undefined,
    isSuccess: fetchCount > 0 && error === undefined,
    refetch,
    mutate,
  };
}
