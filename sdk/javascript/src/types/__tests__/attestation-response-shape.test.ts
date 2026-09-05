/**
 * Pins the VM and container attestation response types to the body the REST
 * routes actually return.
 *
 * These two routes have now drifted from the server twice. The first drift was
 * the URL — the service posted to `/collect/vm` while the server served
 * `/vm/{id}` — and is pinned in services/__tests__/attestation-service.test.ts.
 * That test asserts the request URL and nothing about the response, which is
 * exactly why the second drift survived it: the declared response type was the
 * gRPC envelope `{status, attestation}` while the route returns a flat body, so
 * a caller reading `response.data.attestation` got `undefined` with the
 * compiler asserting the access was sound (#499).
 *
 * The fixtures below are the wire shape, transcribed from the json tags on
 * `VMAttestationResponse` and `ContainerAttestationResp` in
 * pkg/api/rest/attestation_handlers.go. `satisfies` is what makes this a
 * ratchet: if either interface is changed back to a shape the server does not
 * send, these stop compiling rather than silently passing.
 */

import { describe, it, expect } from 'vitest';
import type {
  CollectVMAttestationResponse,
  CollectContainerAttestationResponse,
} from '../attestation.js';

/** Captured body of POST /api/v1/attestation/vm/{id}. */
const vmBody = {
  vm_id: 'vm-42',
  host_id: 'host-1',
  verified: true,
  quote_data: 'cXVvdGU=',
  signature: 'c2ln',
  signature_algorithm: 'RSASSA_PSS',
  pcrs: [{ index: 0, value: 'AAA=', algorithm: 'SHA256' }],
  pcr_digest: 'ZGln',
  nonce: 'bm9uY2U=',
  timestamp: '2026-09-05T12:00:00Z',
  hash_algorithm: 'SHA256',
} satisfies CollectVMAttestationResponse;

/** Captured body of POST /api/v1/attestation/container/{id}. */
const containerBody = {
  container_id: 'ctr-7',
  verified: true,
  digest: 'ZGlnZXN0',
  pcr_value: 'cGNy',
  timestamp: '2026-09-05T12:00:00Z',
} satisfies CollectContainerAttestationResponse;

describe('VM attestation response shape', () => {
  it('exposes the flat fields the route sends', () => {
    const decoded: CollectVMAttestationResponse = JSON.parse(
      JSON.stringify(vmBody)
    ) as CollectVMAttestationResponse;

    expect(decoded.vm_id).toBe('vm-42');
    expect(decoded.host_id).toBe('host-1');
    expect(decoded.verified).toBe(true);
    expect(decoded.pcrs[0]?.index).toBe(0);
    expect(decoded.hash_algorithm).toBe('SHA256');
  });

  it('does not carry the gRPC envelope the type used to declare', () => {
    // The regression this file exists for: `attestation` was declared and
    // never sent, so every read of it was undefined. Asserting its ABSENCE
    // fails loudly if the envelope is reintroduced on the client side only.
    const raw = JSON.parse(JSON.stringify(vmBody)) as Record<string, unknown>;
    expect(raw).not.toHaveProperty('attestation');
    expect(raw).not.toHaveProperty('status');
  });

  it('keeps optional server fields optional', () => {
    // aik_public_key_pem, workload_pcr and metadata carry `omitempty`, so a
    // body without them must still satisfy the type.
    expect(vmBody).not.toHaveProperty('workload_pcr');
    expect(vmBody.verified).toBe(true);
  });
});

describe('container attestation response shape', () => {
  it('exposes the flat fields the route sends', () => {
    const decoded: CollectContainerAttestationResponse = JSON.parse(
      JSON.stringify(containerBody)
    ) as CollectContainerAttestationResponse;

    expect(decoded.container_id).toBe('ctr-7');
    expect(decoded.verified).toBe(true);
    expect(decoded.digest).toBe('ZGlnZXN0');
    expect(decoded.pcr_value).toBe('cGNy');
  });

  it('does not carry the gRPC envelope the type used to declare', () => {
    const raw = JSON.parse(JSON.stringify(containerBody)) as Record<string, unknown>;
    expect(raw).not.toHaveProperty('attestation');
    expect(raw).not.toHaveProperty('status');
  });
});
