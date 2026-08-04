/**
 * React Hooks Index
 *
 * Exports all React hooks for the Trusted Platform SDK.
 *
 * @packageDocumentation
 */

// Generic hooks
export { useApi } from './use-api.js';
export type { UseApiOptions, UseApiResult } from './use-api.js';

export { useMutation } from './use-mutation.js';
export type {
  MutationError,
  UseMutationOptions,
  UseMutationResult,
} from './use-mutation.js';

// Service-specific hooks
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
} from './use-services.js';

// Invitation hooks
export { useInvitation, useInvitationList } from './use-invitation.js';
export type { UseInvitationResult, UseInvitationListOptions } from './use-invitation.js';

// EAB hooks
export { useEAB, useEABList } from './use-eab.js';
export type { UseEABResult, UseEABListOptions } from './use-eab.js';

// QuicBaaS hooks
export {
  useQuicBaaSKV,
  useQuicBaaSVector,
  useQuicBaaSEmbedding,
  useQuicBaaSSecrets,
  useQuicBaaSCache,
  useQuicBaaSHealth,
} from './quicbaas/index.js';

// QuicBaaS TimeSeries hook
export { useQuicBaaSTimeSeries } from './use-quicbaas-timeseries.js';

// QuicBaaS ObjectStorage hooks
export { useQuicBaaSObjectStorage, useQuicBaaSObjectStorageAdmin } from './use-quicbaas-object-storage.js';

// Device Template hooks
export { useDeviceTemplates } from './use-device-template.js';
export type { UseDeviceTemplateResult } from './use-device-template.js';

// Provisioning Session hooks
export { useProvisioningSessions } from './use-provisioning-session.js';
export type { UseProvisioningSessionResult } from './use-provisioning-session.js';
