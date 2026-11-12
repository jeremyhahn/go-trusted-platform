/**
 * Services Index
 *
 * Exports all service classes for the Trusted Platform SDK.
 */

// Base service
export { BaseService, listOptionsToParams, type ListOptions } from './base-service.js';

// Service classes
export { AttestationService } from './attestation-service.js';
export { CAService } from './ca-service.js';
export { ComputeService } from './compute-service.js';
export { DeviceService } from './device-service.js';
export { DNSService } from './dns-service.js';
export { NTPService } from './ntp-service.js';
export type {
  NTPStatus,
  NTPSource,
  NTSServeNameFinding,
  GetNTPStatusResponse,
  ListNTPSourcesResponse,
  StepNTPClockResponse,
} from './ntp-service.js';
export { GatewayService } from './gateway-service.js';
export { IAMService } from './iam-service.js';
export { IDevIDService } from './idevid-service.js';
export { KMSService } from './kms-service.js';
export { OverlayService } from './overlay-service.js';
export { PlatformService } from './platform-service.js';
export { PXEService } from './pxe-service.js';
export { SDNService } from './sdn-service.js';
export { TenantService } from './tenant-service.js';
export { TPMService } from './tpm-service.js';
export { VTPMService } from './vtpm-service.js';
export { VPNService } from './vpn-service.js';
export { InvitationService } from './invitation-service.js';
export { EABService } from './eab-service.js';

// QuicBaaS Services (28 services)
export * from './quicbaas/index.js';
