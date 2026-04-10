/**
 * React bindings for Trusted Platform SDK
 *
 * This module provides React hooks, context, and utilities for using the SDK
 * in React applications. Import from 'trusted-platform-sdk/react' to use.
 *
 * @packageDocumentation
 *
 * @example
 * ```tsx
 * import { PlatformProvider, usePlatformClient, useApi, useMutation, useCA } from 'trusted-platform-sdk/react';
 *
 * // Wrap your app with the provider
 * function App() {
 *   return (
 *     <PlatformProvider config={{ baseUrl: 'https://api.example.com' }}>
 *       <CertificatesPage />
 *     </PlatformProvider>
 *   );
 * }
 *
 * // Use hooks in your components
 * function CertificatesPage() {
 *   const ca = useCA();
 *
 *   // Fetch data with useApi
 *   const { data, isLoading, error, refetch } = useApi(
 *     () => ca.listCertificates(),
 *     [],
 *     { refetchInterval: 30000 }
 *   );
 *
 *   // Mutations with useMutation
 *   const issueCert = useMutation(
 *     (req) => ca.issueCertificate(req),
 *     {
 *       onSuccess: () => refetch(),
 *       onError: (err) => console.error(err),
 *     }
 *   );
 *
 *   if (isLoading) return <Loading />;
 *   if (error) return <Error message={error.message} />;
 *
 *   return (
 *     <div>
 *       <button onClick={() => issueCert.mutate({ subject: { commonName: 'new.example.com' } })}>
 *         Issue Certificate
 *       </button>
 *       <ul>
 *         {data?.certificates.map(cert => (
 *           <li key={cert.serial}>{cert.subject}</li>
 *         ))}
 *       </ul>
 *     </div>
 *   );
 * }
 * ```
 */

// =============================================================================
// Context and Provider
// =============================================================================

export {
  PlatformContext,
  PlatformProvider,
  usePlatformClient,
  usePlatformClientOptional,
} from './context.js';

export type { PlatformContextValue, PlatformProviderProps } from './context.js';

// =============================================================================
// Generic Hooks
// =============================================================================

export { useApi, useMutation } from './hooks/index.js';

export type {
  UseApiOptions,
  UseApiResult,
  MutationError,
  UseMutationOptions,
  UseMutationResult,
} from './hooks/index.js';

// =============================================================================
// Service-Specific Hooks
// =============================================================================

export {
  useAttestation,
  useCA,
  useCompute,
  useDevice,
  useDNS,
  useGateway,
  useIAM,
  useIDevID,
  useKMS,
  useOverlay,
  usePlatform,
  usePXE,
  useSDN,
  useTenant,
  useTPM,
  useVTPM,
  // Invitation hooks
  useInvitation,
  useInvitationList,
  // EAB hooks
  useEAB,
  useEABList,
  // vTPM Instance hooks
  useVTPMInstance,
  useVTPMInstanceList,
  // QuicBaaS hooks
  useQuicBaaSKV,
  useQuicBaaSVector,
  useQuicBaaSEmbedding,
  useQuicBaaSSecrets,
  useQuicBaaSCache,
  useQuicBaaSHealth,
  // QuicBaaS TimeSeries hook
  useQuicBaaSTimeSeries,
  // QuicBaaS ObjectStorage hooks
  useQuicBaaSObjectStorage,
  useQuicBaaSObjectStorageAdmin,
  // Device Template hooks
  useDeviceTemplates,
  // Provisioning Session hooks
  useProvisioningSessions,
} from './hooks/index.js';

export type {
  UseInvitationResult,
  UseInvitationListOptions,
  UseEABResult,
  UseEABListOptions,
  UseVTPMInstanceResult,
  UseVTPMInstanceListOptions,
  UseDeviceTemplateResult,
  UseProvisioningSessionResult,
} from './hooks/index.js';

// =============================================================================
// Re-export Core Types Commonly Needed in React Apps
// =============================================================================

// Client types
export {
  PlatformClient,
  createPlatformClient,
  type PlatformClientConfig,
} from '../client/index.js';

// API response types
export {
  type ApiResponse,
  isSuccessResponse,
  isErrorResponse,
  unwrapResponse,
} from '../types/index.js';

// Error types
export { ApiError, isApiError, ErrorCode, type ErrorCodeValue } from '../errors/index.js';
