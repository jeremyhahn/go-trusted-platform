/**
 * Security service types for CA, KMS, and Attestation
 */

// Certificate Authority (CA) Types
export interface Certificate {
  id: string;
  subject: string;
  issuer: string;
  serialNumber: string;
  type: 'root' | 'intermediate' | 'leaf';
  status: 'active' | 'revoked' | 'expired';
  notBefore: string;
  notAfter: string;
  publicKeyAlgorithm: string;
  signatureAlgorithm: string;
}

export interface CertificateDetail extends Certificate {
  publicKey: string;
  extensions: CertificateExtension[];
  chain: Certificate[];
  pemEncoded: string;
  derEncoded: string;
}

export interface CertificateExtension {
  oid: string;
  name: string;
  critical: boolean;
  value: string;
}

export interface CertificateRequest {
  id: string;
  requester: string;
  subject: string;
  type: 'root' | 'intermediate' | 'leaf';
  requestedAt: string;
  status: 'pending' | 'approved' | 'denied';
  csr: string;
}

export interface IssueCertInput {
  subject: string;
  type: 'root' | 'intermediate' | 'leaf';
  validityDays: number;
  keyAlgorithm: 'RSA-2048' | 'RSA-4096' | 'ECDSA-P256' | 'ECDSA-P384';
  extensions?: Partial<CertificateExtension>[];
}

// Key Management Service (KMS) Types
export interface Key {
  id: string;
  name: string;
  algorithm: 'AES-256' | 'RSA-2048' | 'RSA-4096' | 'ECDSA-P256' | 'ECDSA-P384';
  type: 'symmetric' | 'asymmetric';
  status: 'active' | 'disabled' | 'pending_deletion';
  createdAt: string;
  rotationCount: number;
}

export interface KeyDetail extends Key {
  versions: KeyVersion[];
  usageHistory: KeyUsageEntry[];
  metadata: Record<string, string>;
}

export interface KeyVersion {
  version: number;
  createdAt: string;
  status: 'active' | 'inactive';
}

export interface KeyUsageEntry {
  timestamp: string;
  operation: 'encrypt' | 'decrypt' | 'sign' | 'verify';
  user: string;
}

export interface GenerateKeyInput {
  name: string;
  algorithm: 'AES-256' | 'RSA-2048' | 'RSA-4096' | 'ECDSA-P256' | 'ECDSA-P384';
  metadata?: Record<string, string>;
}

// Attestation Types
export interface Attestation {
  id: string;
  deviceId: string;
  deviceName: string;
  tpmManufacturer: string;
  /**
   * Whether the manifest carries a signature. A manifest is evidence, not a
   * verdict: the verifier's verdict is the device report (#643).
   */
  status: 'signed' | 'unsigned';
  attestedAt: string;
}

export interface AttestationDetail extends Attestation {
  quote: string;
  pcrValues: Record<number, string>;
  eventLog: EventLogEntry[];
  deviceInfo: {
    tpmVersion: string;
    firmwareVersion: string;
    bootMode: string;
  };
}

export interface EventLogEntry {
  pcrIndex: number;
  eventType: string;
  digest: string;
  data: string;
  timestamp?: string;
}

