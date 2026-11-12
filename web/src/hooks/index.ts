/**
 * Hooks barrel export
 *
 * Central export point for all custom hooks.
 * All SDK hooks are re-exported from 'trusted-platform-sdk'.
 */

// Session cookie as an external store (SSR-safe)
export { useSessionToken, useHydrated, notifySessionChanged } from "./use-session-token";

// SDK hooks (exported from main entry point for bundler compatibility)
export {
  // Generic hooks
  useApi,
  useMutation,
  usePlatformClient,
  // Service-specific hooks
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
  useVPN,
  // Invitation hooks
  useInvitation,
  useInvitationList,
  // EAB hooks
  useEAB,
  useEABList,
  // QuicBaaS hooks
  useQuicBaaSKV,
  useQuicBaaSVector,
  useQuicBaaSEmbedding,
  useQuicBaaSSecrets,
  useQuicBaaSCache,
  useQuicBaaSHealth,
  // Note: useQuicBaaSTimeSeries, useQuicBaaSObjectStorage, useQuicBaaSObjectStorageAdmin
  // are available in the SDK but require SDK rebuild. Pages access these via
  // usePlatformClient().timeseries, .objectStorage, .objectStorageAdmin instead.
  // Device template and provisioning session hooks
  useDeviceTemplates,
  useProvisioningSessions,
} from 'trusted-platform-sdk';

export type {
  // Generic hook types
  UseApiOptions,
  UseApiResult,
  MutationError,
  UseMutationOptions,
  UseMutationResult,
  // Invitation types
  UseInvitationResult,
  UseInvitationListOptions,
  // EAB types
  UseEABResult,
  UseEABListOptions,
  // Device template types
  UseDeviceTemplateResult,
  // Provisioning session types
  UseProvisioningSessionResult,
} from 'trusted-platform-sdk';

// Local hooks (not provided by SDK)

// Auth has exactly one implementation, the context in @/contexts/AuthContext.
// The barrel re-exports it so every import path reaches the same provider.
export { useAuth, useOptionalAuth, AuthProvider } from '@/contexts/AuthContext';
export type { User, AuthContextType } from '@/contexts/AuthContext';

export { useToast, toast, dismissToast } from './use-toast';
export {
  useInvitationLookup,
  fetchInvitation,
  fetchInvitationByToken,
  acceptInvitation,
} from './use-invitation-lookup';
export type {
  InvitationDetail,
  AcceptInvitationResult,
  InvitationLookupState,
} from './use-invitation-lookup';
export type { Toast, UseToastReturn } from './use-toast';

export { useReportedGateways } from './use-reported-gateways';
export type {
  ReportedGateway,
  UseReportedGatewaysOptions,
  UseReportedGatewaysResult,
} from './use-reported-gateways';
