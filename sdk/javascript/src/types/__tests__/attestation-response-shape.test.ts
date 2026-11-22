/**
 * Pins the VM and container attestation response types to the body the REST
 * routes actually return.
 *
 * The routes are now served by the protojson AttestationServerRouter
 * (pkg/webservice/v1/rest/attestation/server_router.go). Its collect VM and
 * collect container handlers write the platform.v1
 * CollectVMAttestationResponse / CollectContainerAttestationResponse messages
 * as protojson: a `{ status, attestation }` envelope with lowerCamelCase
 * field names and enum values written by name. That envelope is pinned on the
 * server side by server_router_handlers_test.go ("collect vm" and
 * "collect container").
 *
 * The flat snake_case body these types used to describe came from a REST
 * handler that no longer exists, so every read of `data.verified` or
 * `data.vm_id` was undefined with the compiler calling it sound (#2038).
 * `satisfies` is what makes this a ratchet: if either type drifts back to a
 * shape the server does not send, these fixtures stop compiling.
 */

import { describe, it, expect } from 'vitest';
import type {
  CollectVMAttestationResponse,
  CollectContainerAttestationResponse,
} from '../attestation.js';

/** Body of POST /api/v1/attestation/vm/{id}, as protojson writes it. */
const vmBody = {
  status: { success: true, message: 'ok' },
  attestation: {
    vmId: 'vm-7',
    hostId: 'host-1',
    quoteData: 'cXVvdGU=',
    signature: 'c2ln',
    signatureAlgorithm: 'RSASSA_PSS',
    pcrs: [{ index: 0, value: 'AAA=', algorithm: 'ATTESTATION_HASH_ALGORITHM_SHA256' }],
    pcrDigest: 'ZGln',
    nonce: 'AQID',
    timestamp: '2026-09-05T12:00:00Z',
    aikPublicKey: 'YWlr',
    hashAlgorithm: 'ATTESTATION_HASH_ALGORITHM_SHA256',
  },
} satisfies CollectVMAttestationResponse;

/** Body of POST /api/v1/attestation/container/{id}, as protojson writes it. */
const containerBody = {
  status: { success: true, message: 'ok' },
  attestation: {
    containerId: 'c-9',
    imageId: 'img-1',
    imageDigest: 'sha256:abc',
    digest: 'ZGlnZXN0',
    pcrValue: 'cGNy',
    timestamp: '2026-09-05T12:00:00Z',
  },
} satisfies CollectContainerAttestationResponse;

describe('VM attestation response shape', () => {
  it('exposes the status and attestation envelope the route sends', () => {
    const decoded: CollectVMAttestationResponse = JSON.parse(
      JSON.stringify(vmBody)
    ) as CollectVMAttestationResponse;

    expect(decoded.status.success).toBe(true);
    expect(decoded.attestation?.vmId).toBe('vm-7');
    expect(decoded.attestation?.hashAlgorithm).toBe('ATTESTATION_HASH_ALGORITHM_SHA256');
    expect(decoded.attestation?.pcrs[0]?.algorithm).toBe('ATTESTATION_HASH_ALGORITHM_SHA256');
  });

  it('does not carry the flat snake_case fields the type used to declare', () => {
    const raw = JSON.parse(JSON.stringify(vmBody)) as Record<string, unknown>;
    expect(raw).not.toHaveProperty('vm_id');
    expect(raw).not.toHaveProperty('container_id');
    expect(raw).not.toHaveProperty('verified');
  });
});

describe('container attestation response shape', () => {
  it('exposes the status and attestation envelope the route sends', () => {
    const decoded: CollectContainerAttestationResponse = JSON.parse(
      JSON.stringify(containerBody)
    ) as CollectContainerAttestationResponse;

    expect(decoded.status.success).toBe(true);
    expect(decoded.attestation?.containerId).toBe('c-9');
    expect(decoded.attestation?.pcrValue).toBe('cGNy');
  });

  it('does not carry the flat snake_case fields the type used to declare', () => {
    const raw = JSON.parse(JSON.stringify(containerBody)) as Record<string, unknown>;
    expect(raw).not.toHaveProperty('vm_id');
    expect(raw).not.toHaveProperty('container_id');
    expect(raw).not.toHaveProperty('verified');
  });
});
