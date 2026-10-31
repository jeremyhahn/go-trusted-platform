/**
 * Device Management Types
 * Types for physical/virtual devices, vTPM instances, and IDevID certificates
 */

// ============================================================================
// Device Types
// ============================================================================

export type DeviceType = 'physical' | 'virtual';
export type DeviceStatus = 'online' | 'offline' | 'disabled' | 'unknown';

export interface TPMInfo {
  manufacturer: string;
  version: string;
  firmwareVersion: string;
  hasEK: boolean;
  hasSRK: boolean;
  /**
   * An attestation (IAK/AK) certificate issued by the platform CA is
   * enrolled (`attest_cert`). It is the only trust anchor the quote verifier
   * accepts; without it the device is denied at attest time (#374, #404).
   */
  hasAKCert: boolean;
}

export interface Device {
  id: string;
  name: string;
  type: DeviceType;
  /** Hardware model (e.g. "SuperMicro X10"). Populated from the TCG
   *  CSR ProductModel field at enrollment time. */
  model?: string;
  serial?: string;
  status: DeviceStatus;
  /** The lifecycle state the control plane records (`attested`,
   *  `suspended`, `revoked`, ...). `status` folds it into a badge; the
   *  Enable/Disable control needs the state itself (#250). */
  state?: string;
  lastSeen?: string;
  registeredAt: string;
  tpm?: TPMInfo;
}

export interface EndorsementKey {
  id: string;
  keyType: 'RSA' | 'ECC';
  publicKey: string;
  createdAt: string;
}

export interface AttestationRecord {
  id: string;
  timestamp: string;
  status: 'passed' | 'failed' | 'pending';
  nonce: string;
  pcrValues: Record<number, string>;
  signature: string;
  quote: string;
}

export interface DeviceCertificate {
  id: string;
  type: 'EK' | 'AIK' | 'IDevID' | 'LDevID';
  subject: string;
  serialNumber: string;
  issuedAt: string;
  expiresAt: string;
  status: 'active' | 'revoked' | 'expired';
}

export interface DeviceDetail extends Device {
  description?: string;
  tags?: string[];
  endorsementKey?: EndorsementKey;
  /** PEM of the enrolled attestation certificate, when one is recorded */
  attestCert?: string;
  /** mTLS peer address (host:port) the last heartbeat arrived from; the collector's dial candidate after DNS */
  lastHeartbeatAddr?: string;
  certificates: DeviceCertificate[];
  attestationHistory: AttestationRecord[];
  metadata?: Record<string, string>;
}

export interface UpdateDeviceInput {
  name?: string;
  description?: string;
  tags?: string[];
  status?: DeviceStatus;
}

export interface AttestationResult {
  id: string;
  status: 'passed' | 'failed';
  timestamp: string;
  pcrValues: Record<number, string>;
  quote: string;
  signature: string;
  verificationDetails: string;
}

// ============================================================================
// vTPM Types
// ============================================================================

export type VTPMState = 'active' | 'sealed' | 'migrating' | 'suspended';

export interface VTPM {
  id: string;
  name: string;
  vmId: string;
  vmName: string;
  state: VTPMState;
  pcrProfile: string;
  createdAt: string;
  updatedAt?: string;
}

export interface PCRValue {
  index: number;
  value: string;
  description?: string;
}

export interface SealedData {
  id: string;
  name: string;
  description?: string;
  pcrIndices: number[];
  createdAt: string;
  dataSize: number;
}

export interface VTPMDetail extends VTPM {
  description?: string;
  pcrValues: PCRValue[];
  sealedData: SealedData[];
  migrations: VTPMMigration[];
  metadata?: Record<string, string>;
}

export interface VTPMMigration {
  id: string;
  sourceHost: string;
  targetHost: string;
  status: 'pending' | 'in_progress' | 'completed' | 'failed';
  startedAt: string;
  completedAt?: string;
  error?: string;
}

export interface CreateVTPMInput {
  name: string;
  vmId: string;
  vmName: string;
  description?: string;
  pcrProfile?: string;
}

export interface SealDataInput {
  name: string;
  data: string;
  description?: string;
  pcrIndices: number[];
  pcrValues?: Record<number, string>;
}

export interface MigrateVTPMInput {
  targetHost: string;
  targetVMId: string;
}

// ============================================================================
// IDevID Types
// ============================================================================

export type IDevIDStatus = 'active' | 'revoked' | 'expired' | 'pending';

export interface IDevID {
  id: string;
  deviceId: string;
  deviceName: string;
  subject: string;
  serialNumber: string;
  status: IDevIDStatus;
  issuedAt: string;
  expiresAt: string;
  renewedFrom?: string;
}

export interface CertificateChain {
  certificate: string;
  issuer: string;
  intermediate: string[];
  root: string;
}

export interface IDevIDDetail extends IDevID {
  certificate: string;
  publicKey: string;
  keyAlgorithm: 'RSA' | 'ECC';
  keySize: number;
  signatureAlgorithm: string;
  chain: CertificateChain;
  extensions: Record<string, string>;
  renewals: IDevIDRenewal[];
}

export interface IDevIDRenewal {
  id: string;
  renewedAt: string;
  previousCertId: string;
  newCertId: string;
  reason: string;
}

export interface IssueIDevIDInput {
  deviceId: string;
  subject: string;
  validityDays: number;
  keyAlgorithm: 'RSA' | 'ECC';
  keySize?: number;
  extensions?: Record<string, string>;
}

export interface RenewIDevIDInput {
  validityDays: number;
  reason: string;
}

// ============================================================================
// API Response Types
// ============================================================================

export interface DeviceFilters {
  type?: DeviceType;
  status?: DeviceStatus;
  search?: string;
}

export interface VTPMFilters {
  state?: VTPMState;
  vmId?: string;
  search?: string;
}

export interface IDevIDFilters {
  status?: IDevIDStatus;
  deviceId?: string;
  expiringDays?: number;
  search?: string;
}
