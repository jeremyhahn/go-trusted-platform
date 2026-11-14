/**
 * Mutation hook for POST/PUT/PATCH/DELETE operations
 *
 * Provides a declarative way to perform mutations with automatic
 * state management for loading, error, and success states.
 *
 * @packageDocumentation
 */

import { useState, useCallback, useRef, useEffect } from 'react';
import type { ApiResponse } from '../../types/api.js';
import type { ApiError } from '../../errors/api-error.js';

/**
 * Error type for mutations
 */
export interface MutationError {
  /** Error code */
  code: string;
  /** Error message */
  message: string;
  /** HTTP status code if available */
  status?: number;
  /** Original error */
  cause?: unknown;
}

/**
 * Options for the useMutation hook
 *
 * @typeParam TData - The type of data returned by the mutation
 * @typeParam TVariables - The type of variables passed to the mutation
 */
export interface UseMutationOptions<TData, TVariables> {
  /**
   * Callback fired when mutation completes successfully
   */
  onSuccess?: (data: TData, variables: TVariables) => void;

  /**
   * Callback fired when mutation fails
   */
  onError?: (error: MutationError, variables: TVariables) => void;

  /**
   * Callback fired after mutation completes (success or error)
   */
  onSettled?: (
    data: TData | undefined,
    error: MutationError | undefined,
    variables: TVariables
  ) => void;

  /**
   * Callback fired before mutation starts.
   * Return value is used for rollback in case of error.
   */
  onMutate?: (variables: TVariables) => unknown;
}

/**
 * Result returned by the useMutation hook
 *
 * @typeParam TData - The type of data returned by the mutation
 * @typeParam TVariables - The type of variables passed to the mutation
 */
export interface UseMutationResult<TData, TVariables> {
  /** The mutation result data */
  data: TData | undefined;

  /** The error if mutation failed */
  error: MutationError | undefined;

  /** The variables used in the last mutation call */
  variables: TVariables | undefined;

  /** Whether the mutation is currently executing */
  isLoading: boolean;

  /** Whether the mutation has completed at least once, regardless of outcome */
  isSettled: boolean;

  /** Whether the last mutation was an error */
  isError: boolean;

  /** Whether the last mutation was successful */
  isSuccess: boolean;

  /** Whether the mutation is idle (not yet called) */
  isIdle: boolean;

  /**
   * Fire-and-forget mutation trigger.
   * Errors are handled via onError callback.
   */
  mutate: (variables: TVariables) => void;

  /**
   * Async mutation trigger that returns a Promise.
   * Throws on error for try/catch handling.
   */
  mutateAsync: (variables: TVariables) => Promise<TData>;

  /**
   * Reset the mutation state to idle
   */
  reset: () => void;
}

/**
 * Mutation status types
 */
type MutationStatus = 'idle' | 'loading' | 'success' | 'error';

/**
 * Hook for mutations (POST/PUT/PATCH/DELETE operations)
 *
 * Provides a way to perform data mutations with automatic state management
 * for loading, error, and success states.
 *
 * @typeParam TData - The type of data returned by the mutation
 * @typeParam TVariables - The type of variables passed to the mutation
 * @param mutationFn - Function that performs the mutation
 * @param options - Configuration options
 * @returns Result object with mutation trigger and state
 *
 * @example
 * ```tsx
 * // Basic usage
 * function CreateCertificateForm() {
 *   const client = usePlatformClient();
 *
 *   const issueCert = useMutation(
 *     (req: CertificateRequest) => client.ca.issueCertificate(req),
 *     {
 *       onSuccess: (cert) => {
 *         toast.success(`Certificate ${cert.serial} issued`);
 *       },
 *       onError: (error) => {
 *         toast.error(`Failed: ${error.message}`);
 *       },
 *     }
 *   );
 *
 *   const handleSubmit = (data: FormData) => {
 *     issueCert.mutate({
 *       subject: { commonName: data.cn },
 *       validDays: 365,
 *     });
 *   };
 *
 *   return (
 *     <form onSubmit={handleSubmit}>
 *       <button type="submit" disabled={issueCert.isLoading}>
 *         {issueCert.isLoading ? 'Issuing...' : 'Issue Certificate'}
 *       </button>
 *     </form>
 *   );
 * }
 *
 * // Async usage with try/catch
 * const handleClick = async () => {
 *   try {
 *     const result = await issueCert.mutateAsync({ subject: { cn: 'example.com' } });
 *     console.log('Certificate issued:', result.serial);
 *   } catch (error) {
 *     console.error('Failed to issue certificate:', error);
 *   }
 * };
 * ```
 */
export function useMutation<TData, TVariables>(
  mutationFn: (variables: TVariables) => Promise<ApiResponse<TData>>,
  options?: UseMutationOptions<TData, TVariables>
): UseMutationResult<TData, TVariables> {
  const [data, setData] = useState<TData | undefined>(undefined);
  const [error, setError] = useState<MutationError | undefined>(undefined);
  const [variables, setVariables] = useState<TVariables | undefined>(undefined);
  const [status, setStatus] = useState<MutationStatus>('idle');

  // Use refs to avoid stale closures
  const optionsRef = useRef(options);
  const isMountedRef = useRef(true);
  const mutationFnRef = useRef(mutationFn);

  useEffect(() => {
    optionsRef.current = options;
  }, [options]);

  useEffect(() => {
    mutationFnRef.current = mutationFn;
  }, [mutationFn]);

  useEffect(() => {
    isMountedRef.current = true;
    return () => {
      isMountedRef.current = false;
    };
  }, []);

  /**
   * Convert various error types to MutationError
   */
  const toMutationError = useCallback((err: unknown): MutationError => {
    // Handle ApiError from SDK
    if (err !== null && typeof err === 'object' && 'code' in err && 'message' in err) {
      const apiErr = err as ApiError;
      const result: MutationError = {
        code: String(apiErr.code),
        message: String(apiErr.message),
        cause: err,
      };
      if (typeof apiErr.status === 'number') {
        result.status = apiErr.status;
      }
      return result;
    }

    // Handle standard Error
    if (err instanceof Error) {
      return {
        code: 'MUTATION_ERROR',
        message: err.message,
        cause: err,
      };
    }

    // Handle unknown error types
    return {
      code: 'UNKNOWN_ERROR',
      message: String(err),
      cause: err,
    };
  }, []);

  /**
   * Async mutation that returns a Promise
   */
  const mutateAsync = useCallback(
    async (vars: TVariables): Promise<TData> => {
      setStatus('loading');
      setVariables(vars);
      setError(undefined);

      // Call onMutate callback (can be used for optimistic updates)
      optionsRef.current?.onMutate?.(vars);

      // Report an error once, through state and the callbacks, then reject
      // with it. The callbacks run outside the try/catch below, so a
      // callback that throws (even rethrowing the error it was given)
      // propagates as is and is never reported a second time.
      // A settle callback that throws after a success is reported the same
      // way, with settle=false so it is not called a second time.
      const fail = (mutationError: MutationError, settle = true): never => {
        setError(mutationError);
        setStatus('error');
        optionsRef.current?.onError?.(mutationError, vars);
        if (settle) {
          optionsRef.current?.onSettled?.(undefined, mutationError, vars);
        }
        throw mutationError;
      };

      // Only the mutation function sits inside the try: its failures,
      // whether thrown or rejected, are mapped to a MutationError here.
      let response: ApiResponse<TData>;
      try {
        response = await mutationFnRef.current(vars);
      } catch (err) {
        // After unmount, rethrow the original rejection without callbacks
        if (!isMountedRef.current) {
          throw err;
        }
        return fail(toMutationError(err));
      }

      // Check if component is still mounted
      if (!isMountedRef.current) {
        throw new Error('Component unmounted during mutation');
      }

      // Handle API error response
      if (response.error !== undefined) {
        return fail(toMutationError(response.error));
      }

      // Handle successful response
      if (response.data !== undefined) {
        setData(response.data);
        setStatus('success');
        // A throwing onSuccess is reported once, as a failure of the mutation
        try {
          optionsRef.current?.onSuccess?.(response.data, vars);
        } catch (err) {
          return fail(toMutationError(err));
        }
        try {
          optionsRef.current?.onSettled?.(response.data, undefined, vars);
        } catch (err) {
          // onSettled already ran once: report the failure without calling it again
          return fail(toMutationError(err), false);
        }
        return response.data;
      }

      // Handle unexpected empty response
      return fail({
        code: 'EMPTY_RESPONSE',
        message: 'Mutation returned empty response',
      });
    },
    [toMutationError]
  );

  /**
   * Fire-and-forget mutation
   */
  const mutate = useCallback(
    (vars: TVariables) => {
      mutateAsync(vars).catch(() => {
        // Error already handled via callbacks and state
      });
    },
    [mutateAsync]
  );

  /**
   * Reset mutation state
   */
  const reset = useCallback(() => {
    setData(undefined);
    setError(undefined);
    setVariables(undefined);
    setStatus('idle');
  }, []);

  return {
    data,
    error,
    variables,
    isLoading: status === 'loading',
    isSettled: status === 'success' || status === 'error',
    isError: status === 'error',
    isSuccess: status === 'success',
    isIdle: status === 'idle',
    mutate,
    mutateAsync,
    reset,
  };
}
