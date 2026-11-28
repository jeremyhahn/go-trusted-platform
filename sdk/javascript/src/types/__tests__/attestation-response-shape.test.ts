/**
 * Pins the VM and container attestation response types to the body the REST
 * routes actually return.
 *
 * These two routes have drifted from the server more than once. The first
 * drift was the URL, pinned in services/__tests__/attestation-service.test.ts.
 * The second was the response shape: the flat snake_case body of the removed
 * pkg/api/rest/attestation_handlers.go. The routes are now served by
 * AttestationServerRouter (pkg/webservice/v1/rest/attestation), which writes
 * the protobuf response through protorest.WriteSuccess as protojson: the
 * `{status, attestation}` envelope with lowerCamel field names and enum values
 * by their proto name. Neither collect response carries a verdict: collecting
 * evidence is not verifying it.
 *
 * `satisfies` is what makes this a ratchet: if either type is changed back to
 * a shape the server does not send, these fixtures stop compiling rather than
 * silently passing.
 */

import { describe, it, expect } from 'vitest';
import type {
  CollectVMAttestationResponse,
  CollectContainerAttestationResponse,
} from '../attestation.js';

/** Captured body of POST /api/v1/attestation/vm/{id}. */
const vmBody = {
  status: { success: true, message: 'ok' },
  attestation: {
    vmId: 'vm-42',
    hostId: 'host-1',
    quoteData: 'cXVvdGU=',
    signature: 'c2ln',
    signatureAlgorithm: 'RSASSA_PSS',
    pcrs: [{ index: 0, value: 'AAA=', algorithm: 'ATTESTATION_HASH_ALGORITHM_SHA256' }],
    pcrDigest: 'ZGln',
    nonce: 'bm9uY2U=',
    timestamp: '2026-09-05T12:00:00Z',
    aikPublicKey: 'YWs=',
    hashAlgorithm: 'ATTESTATION_HASH_ALGORITHM_SHA256',
  },
} satisfies CollectVMAttestationResponse;

/** Captured body of POST /api/v1/attestation/container/{id}. */
const containerBody = {
  status: { success: true, message: 'ok' },
  attestation: {
    containerId: 'ctr-7',
    imageId: 'img-1',
    imageDigest: 'sha256:00',
    digest: 'ZGlnZXN0',
    pcrValue: 'cGNy',
    timestamp: '2026-09-05T12:00:00Z',
  },
} satisfies CollectContainerAttestationResponse;

describe('VM attestation response shape', () => {
  it('carries the status and attestation envelope the route sends', () => {
    const decoded: CollectVMAttestationResponse = JSON.parse(
      JSON.stringify(vmBody)
    ) as CollectVMAttestationResponse;

    expect(decoded.status.success).toBe(true);
    expect(decoded.attestation?.vmId).toBe('vm-42');
    expect(decoded.attestation?.hostId).toBe('host-1');
    expect(decoded.attestation?.pcrs[0]?.index).toBe(0);
    expect(decoded.attestation?.hashAlgorithm).toBe('ATTESTATION_HASH_ALGORITHM_SHA256');
  });

  it('has no verified field: neither collect response carries a verdict', () => {
    const raw = JSON.parse(JSON.stringify(vmBody)) as Record<string, unknown>;
    expect(raw).not.toHaveProperty('verified');
    expect(raw).not.toHaveProperty('vm_id');
    expect(raw.attestation).not.toHaveProperty('verified');
  });
});

describe('container attestation response shape', () => {
  it('carries the status and attestation envelope the route sends', () => {
    const decoded: CollectContainerAttestationResponse = JSON.parse(
      JSON.stringify(containerBody)
    ) as CollectContainerAttestationResponse;

    expect(decoded.status.success).toBe(true);
    expect(decoded.attestation?.containerId).toBe('ctr-7');
    expect(decoded.attestation?.imageDigest).toBe('sha256:00');
    expect(decoded.attestation?.digest).toBe('ZGlnZXN0');
    expect(decoded.attestation?.pcrValue).toBe('cGNy');
  });

  it('has no verified field: neither collect response carries a verdict', () => {
    const raw = JSON.parse(JSON.stringify(containerBody)) as Record<string, unknown>;
    expect(raw).not.toHaveProperty('verified');
    expect(raw).not.toHaveProperty('container_id');
    expect(raw.attestation).not.toHaveProperty('verified');
  });
});
