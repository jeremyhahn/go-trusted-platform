/**
 * Remote-access VPN types
 *
 * The operator control plane of `VPNService` (pkg/api/grpc/proto/vpn.proto),
 * as the REST routes under /api/v1/vpn encode it: protojson with camelCase
 * field names and every field present. protojson writes 64-bit integers as
 * decimal strings, so the `*Unix` timestamps and the admission counters are
 * strings here; 32-bit integers stay numbers. See docs/vpn/api.md.
 */

/**
 * A device enrolled as a VPN peer of a tenant
 */
export interface VPNPeer {
  tenantId: string;
  deviceId: string;
  /** Narrows the gateway's allow-to zones; empty means every allowed zone */
  zones: string[];
  /** First enrolment time, Unix seconds as a decimal string; set by the service */
  enrolledAtUnix: string;
}

/**
 * A tenant posture policy: a Rego module in package vpn.posture
 */
export interface VPNPosturePolicy {
  tenantId: string;
  name: string;
  module: string;
  /** Last write time, Unix seconds as a decimal string; set by the service */
  updatedAtUnix: string;
}

/**
 * One active address lease a gateway holds for a peer
 */
export interface VPNLease {
  id: string;
  tenantId: string;
  deviceId: string;
  address: string;
  /** The tunnel that carries the session: masque or wireguard */
  dataPlane: string;
  zones: string[];
  issuedAtUnix: string;
  expiresAtUnix: string;
  renewals: number;
}

/**
 * One enrolment a gateway refused, and why
 */
export interface VPNRejectedPeer {
  tenantId: string;
  deviceId: string;
  reason: string;
}

/**
 * The VPN section of one gateway's last telemetry report
 */
export interface VPNGatewayStatus {
  gatewayId: string;
  reportedAtUnix: string;
  /** False when the gateway reports telemetry without a VPN section; the rest is then zero */
  reporting: boolean;
  running: boolean;
  admissions: string;
  refusals: string;
  lastRefusal: string;
  enrolledPeers: number;
  leasesByDataPlane: Record<string, number>;
  leases: VPNLease[];
  posturePolicyErrors: string[];
  rejectedPeers: VPNRejectedPeer[];
}

/**
 * Request to enrol a device, or to replace the zones of its enrolment
 */
export interface EnrolVPNPeerRequest {
  tenantId: string;
  deviceId: string;
  zones?: string[];
}

export interface EnrolVPNPeerResponse {
  peer: VPNPeer;
}

export interface ListVPNPeersResponse {
  peers: VPNPeer[];
}

export type RevokeVPNPeerResponse = Record<string, never>;

export interface GetVPNStatusResponse {
  gateways: VPNGatewayStatus[];
}

/**
 * Request to create or replace a tenant posture policy
 */
export interface SetVPNPosturePolicyRequest {
  tenantId: string;
  name: string;
  /** Rego source; must compile and declare package vpn.posture */
  module: string;
}

export interface GetVPNPosturePolicyResponse {
  policy: VPNPosturePolicy;
}

export interface SetVPNPosturePolicyResponse {
  policy: VPNPosturePolicy;
}

export type DeleteVPNPosturePolicyResponse = Record<string, never>;

export interface ListVPNPosturePoliciesResponse {
  policies: VPNPosturePolicy[];
}
