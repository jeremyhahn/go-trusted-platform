/**
 * Service-Specific React Hooks
 *
 * Convenience hooks that provide access to individual services from
 * the PlatformClient with built-in useApi and useMutation patterns.
 *
 * @packageDocumentation
 */

import type {
  AttestationService,
  CAService,
  ComputeService,
  DeviceService,
  DNSService,
  GatewayService,
  IAMService,
  IDevIDService,
  KMSService,
  OverlayService,
  PlatformService,
  PXEService,
  SDNService,
  TenantService,
  TPMService,
  VTPMService,
} from '../../services/index.js';
import { usePlatformClient } from '../context.js';

/**
 * Hook to access the Attestation service
 *
 * @returns The AttestationService instance from the current client
 *
 * @example
 * ```tsx
 * function QuoteVerifier() {
 *   const attestation = useAttestation();
 *
 *   const handleVerify = async (quote: string) => {
 *     const result = await attestation.verifyQuote({ quote });
 *     console.log('Verification result:', result.data);
 *   };
 *
 *   // ... render
 * }
 * ```
 */
export function useAttestation(): AttestationService {
  const client = usePlatformClient();
  return client.attestation;
}

/**
 * Hook to access the Certificate Authority service
 *
 * @returns The CAService instance from the current client
 *
 * @example
 * ```tsx
 * function CertificateManager() {
 *   const ca = useCA();
 *
 *   const issueCert = async (commonName: string) => {
 *     const result = await ca.issueCertificate({
 *       subject: { commonName },
 *       validDays: 365,
 *     });
 *     return result.data;
 *   };
 *
 *   // ... render
 * }
 * ```
 */
export function useCA(): CAService {
  const client = usePlatformClient();
  return client.ca;
}

/**
 * Hook to access the Compute service
 *
 * @returns The ComputeService instance from the current client
 *
 * @example
 * ```tsx
 * function VMManager() {
 *   const compute = useCompute();
 *
 *   const createVM = async (name: string) => {
 *     const result = await compute.createVM({
 *       config: { name, cpu: { cores: 2 }, memory: { sizeMb: 4096 } },
 *     });
 *     return result.data;
 *   };
 *
 *   // ... render
 * }
 * ```
 */
export function useCompute(): ComputeService {
  const client = usePlatformClient();
  return client.compute;
}

/**
 * Hook to access the Device service
 *
 * @returns The DeviceService instance from the current client
 *
 * @example
 * ```tsx
 * function DeviceInventory() {
 *   const device = useDevice();
 *
 *   const fetchDevices = async () => {
 *     const result = await device.listDevices({ page: 1, pageSize: 50 });
 *     return result.data?.devices ?? [];
 *   };
 *
 *   // ... render
 * }
 * ```
 */
export function useDevice(): DeviceService {
  const client = usePlatformClient();
  return client.device;
}

/**
 * Hook to access the DNS service
 *
 * @returns The DNSService instance from the current client
 *
 * @example
 * ```tsx
 * function DNSManager() {
 *   const dns = useDNS();
 *
 *   const createRecord = async (zone: string, name: string, ip: string) => {
 *     const result = await dns.createRecord({
 *       zone,
 *       record: { name, type: 'A', value: ip },
 *     });
 *     return result.data;
 *   };
 *
 *   // ... render
 * }
 * ```
 */
export function useDNS(): DNSService {
  const client = usePlatformClient();
  return client.dns;
}

/**
 * Hook to access the Gateway service
 *
 * @returns The GatewayService instance from the current client
 *
 * @example
 * ```tsx
 * function GatewayDashboard() {
 *   const gateway = useGateway();
 *
 *   const getStatus = async () => {
 *     const result = await gateway.getStatus();
 *     return result.data;
 *   };
 *
 *   // ... render
 * }
 * ```
 */
export function useGateway(): GatewayService {
  const client = usePlatformClient();
  return client.gateway;
}

/**
 * Hook to access the IAM service
 *
 * @returns The IAMService instance from the current client
 *
 * @example
 * ```tsx
 * function UserManager() {
 *   const iam = useIAM();
 *
 *   const createUser = async (email: string, name: string) => {
 *     const result = await iam.createUser({
 *       tenantId: 'default',
 *       email,
 *       name,
 *       roles: ['user'],
 *     });
 *     return result.data;
 *   };
 *
 *   // ... render
 * }
 * ```
 */
export function useIAM(): IAMService {
  const client = usePlatformClient();
  return client.iam;
}

/**
 * Hook to access the IDevID service
 *
 * @returns The IDevIDService instance from the current client
 *
 * @example
 * ```tsx
 * function DeviceIdentity() {
 *   const idevid = useIDevID();
 *
 *   const getIdentity = async (deviceId: string) => {
 *     const result = await idevid.getDeviceIdentity(deviceId);
 *     return result.data;
 *   };
 *
 *   // ... render
 * }
 * ```
 */
export function useIDevID(): IDevIDService {
  const client = usePlatformClient();
  return client.idevid;
}

/**
 * Hook to access the KMS service
 *
 * @returns The KMSService instance from the current client
 *
 * @example
 * ```tsx
 * function KeyManager() {
 *   const kms = useKMS();
 *
 *   const createKey = async (keyId: string, algorithm: string) => {
 *     const result = await kms.createKey({
 *       keyId,
 *       algorithm,
 *       usage: ['sign', 'verify'],
 *     });
 *     return result.data;
 *   };
 *
 *   // ... render
 * }
 * ```
 */
export function useKMS(): KMSService {
  const client = usePlatformClient();
  return client.kms;
}

/**
 * Hook to access the Overlay service
 *
 * @returns The OverlayService instance from the current client
 *
 * @example
 * ```tsx
 * function NetworkOverlay() {
 *   const overlay = useOverlay();
 *
 *   const createVXLAN = async (vni: number, name: string) => {
 *     const result = await overlay.createVXLAN({ vni, name });
 *     return result.data;
 *   };
 *
 *   // ... render
 * }
 * ```
 */
export function useOverlay(): OverlayService {
  const client = usePlatformClient();
  return client.overlay;
}

/**
 * Hook to access the Platform service
 *
 * @returns The PlatformService instance from the current client
 *
 * @example
 * ```tsx
 * function SystemHealth() {
 *   const platform = usePlatform();
 *
 *   const checkHealth = async () => {
 *     const result = await platform.getHealth({ includeServices: true });
 *     return result.data;
 *   };
 *
 *   // ... render
 * }
 * ```
 */
export function usePlatform(): PlatformService {
  const client = usePlatformClient();
  return client.platform;
}

/**
 * Hook to access the PXE service
 *
 * @returns The PXEService instance from the current client
 *
 * @example
 * ```tsx
 * function PXEBoot() {
 *   const pxe = usePXE();
 *
 *   const getBootConfig = async (mac: string) => {
 *     const result = await pxe.getBootConfig(mac);
 *     return result.data;
 *   };
 *
 *   // ... render
 * }
 * ```
 */
export function usePXE(): PXEService {
  const client = usePlatformClient();
  return client.pxe;
}

/**
 * Hook to access the SDN service
 *
 * @returns The SDNService instance from the current client
 *
 * @example
 * ```tsx
 * function SDNController() {
 *   const sdn = useSDN();
 *
 *   const createBridge = async (name: string) => {
 *     const result = await sdn.createBridge({ name });
 *     return result.data;
 *   };
 *
 *   // ... render
 * }
 * ```
 */
export function useSDN(): SDNService {
  const client = usePlatformClient();
  return client.sdn;
}

/**
 * Hook to access the Tenant service
 *
 * @returns The TenantService instance from the current client
 *
 * @example
 * ```tsx
 * function TenantManager() {
 *   const tenant = useTenant();
 *
 *   const createTenant = async (name: string) => {
 *     const result = await tenant.createTenant({ name });
 *     return result.data;
 *   };
 *
 *   // ... render
 * }
 * ```
 */
export function useTenant(): TenantService {
  const client = usePlatformClient();
  return client.tenant;
}

/**
 * Hook to access the TPM service
 *
 * @returns The TPMService instance from the current client
 *
 * @example
 * ```tsx
 * function TPMOperations() {
 *   const tpm = useTPM();
 *
 *   const sealData = async (data: string, pcrs: number[]) => {
 *     const result = await tpm.seal({
 *       data: btoa(data),
 *       cn: 'sealed-secret',
 *       pcrIndices: pcrs,
 *     });
 *     return result.data;
 *   };
 *
 *   // ... render
 * }
 * ```
 */
export function useTPM(): TPMService {
  const client = usePlatformClient();
  return client.tpm;
}

/**
 * Hook to access the vTPM service
 *
 * @returns The VTPMService instance from the current client
 *
 * @example
 * ```tsx
 * function VirtualTPM() {
 *   const vtpm = useVTPM();
 *
 *   const createBundle = async (hostname: string) => {
 *     const result = await vtpm.createBundle({
 *       options: { hostname, ekAlgorithm: 'RSA' },
 *     });
 *     return result.data;
 *   };
 *
 *   // ... render
 * }
 * ```
 */
export function useVTPM(): VTPMService {
  const client = usePlatformClient();
  return client.vtpm;
}
