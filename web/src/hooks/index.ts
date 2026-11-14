/**
 * Hooks barrel export
 *
 * Central export point for all custom hooks.
 * All SDK hooks are re-exported from 'trusted-platform-sdk'.
 */

// Session cookie as an external store (SSR-safe)
export { useSessionToken, useHydrated, notifySessionChanged } from "./use-session-token";

// NTP status, sources and clock step (#1682)
export { useNTP } from "./use-ntp";
export type { NTPStatus, NTPSource, NTPStatusResponse, NTPSourcesResponse } from "./use-ntp";

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
export type { Toast, UseToastReturn } from './use-toast';

export { useKmsOps, base64ToText, KMS_SETTABLE_KEY_STATUSES } from './use-kms-ops';
export type {
  UseKmsOpsResult,
  KmsKeyVersion,
  KmsBackendStatus,
  KmsImportKeyInput,
} from './use-kms-ops';
export { useTPMOps, textToBase64, base64ToHex } from './use-tpm-ops';
// textToBase64 and base64ToHex come from use-tpm-ops (main) above.
export { useVTPMRuntime, base64ToText, hexToBase64 } from './use-vtpm-runtime';
export type { VTPMRunState } from './use-vtpm-runtime';
export {
  useContainerOps,
  useVMAttestationVerify,
  randomNonce,
  decodeOutput,
  splitCommand,
} from './use-container-ops';
export type { UseContainerOpsResult } from './use-container-ops';
export { useAttestationCollect, newAttestationNonce } from './use-attestation-collect';
export type {
  AttestationCollectOperation,
  AttestationCollectState,
  UseAttestationCollectResult,
} from './use-attestation-collect';
export { useBMC, bmcUrl } from './use-bmc';
export type { BMCState, BMCPart, UseBMCResult } from './use-bmc';

export { useGatewayBgp } from './use-gateway-bgp';
export type {
  GatewayBGPPeer,
  GatewayAnnouncedPrefix,
  GatewayIPAllocation,
  UseGatewayBgpResult,
} from './use-gateway-bgp';
export { useReportedGateways } from './use-reported-gateways';

export {
  useInvitationById,
  useInvitationByToken,
  toInvitationView,
} from './use-invitation-detail';
export type { InvitationView, InvitationWire } from './use-invitation-detail';
export { useOverlayVteps } from './use-overlay-vteps';
export { useRegistry, encodeRepository } from './use-registry';
export type {
  RegistryHealthCode,
  RegistryComponent,
  RegistryStatus,
  RegistryTags,
  UseRegistryResult,
} from './use-registry';
export { useSwitchPorts } from './use-switch-ports';
export type { UseSwitchPortsResult } from './use-switch-ports';
export { usePolicyTools, splitList } from './use-policy-tools';
export type { ValidatePolicyInput, TestPolicyInput } from './use-policy-tools';
export { useDeviceTemplateActions } from './use-device-template-actions';
export { useSDNBridge } from './use-sdn-bridge';
export type { UseSDNBridgeResult } from './use-sdn-bridge';
export type {
  ReportedGateway,
  UseReportedGatewaysOptions,
  UseReportedGatewaysResult,
} from './use-reported-gateways';
