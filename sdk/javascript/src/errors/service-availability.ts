import type { ApiErrorDetails } from './types.js';

/**
 * Stable discriminator the platform emits in the REST error envelope's
 * `reason` field when a surface is dark because its backing service was
 * never wired into the daemon on this node.
 *
 * Mirrors `ReasonServiceNotConfigured` in
 * `pkg/webservice/v1/service_registry.go`. The envelope's `error` text
 * is operator-facing prose and is deliberately NOT part of the
 * contract — branch on this value, never on the message.
 */
export const SERVICE_NOT_CONFIGURED = 'SERVICE_NOT_CONFIGURED';

/** Subset of the error shape this predicate reads. */
interface ServiceErrorShape {
  status?: unknown;
  details?: ApiErrorDetails;
}

/**
 * Returns true when the error is the platform's structured 503 for a
 * service that is not configured on this node.
 *
 * Both conditions are necessary: the HTTP status must be 503, and the
 * envelope must carry the {@link SERVICE_NOT_CONFIGURED} discriminator.
 * A live service answering 503 for a transient outage carries no
 * discriminator and is therefore a real error; an error carrying the
 * discriminator under any other status is malformed and also rejected.
 *
 * Accepts both the `ApiError` instance the client throws and the plain
 * `ApiResponse.error` object `useApi` hands to callbacks — both carry
 * `status` and `details`.
 */
export function isServiceNotConfigured(err: unknown): boolean {
  if (err === null || typeof err !== 'object') {
    return false;
  }
  const e = err as ServiceErrorShape;
  if (e.status !== 503) {
    return false;
  }
  return e.details?.reason === SERVICE_NOT_CONFIGURED;
}
