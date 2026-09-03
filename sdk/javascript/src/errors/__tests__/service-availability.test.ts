/**
 * Unit tests for the "service not configured" predicate.
 *
 * The platform's REST service registry answers a structured 503 for a
 * surface whose backing service was never wired on this node. The WebUI
 * renders that as an informational state instead of an error, so the
 * predicate must be exact: matching a transient 503, or the registry's
 * prose under a different status, would tell operators a broken node is
 * healthy.
 */

import { describe, it, expect } from 'vitest';
import { SERVICE_NOT_CONFIGURED, isServiceNotConfigured } from '../service-availability.js';

/** The registry's operator-facing prose — deliberately not a contract. */
const registryProse = 'compute service not configured by daemon — REST surface is dark';

describe('isServiceNotConfigured', () => {
  it('accepts the sentinel 503 carrying the discriminator', () => {
    expect(
      isServiceNotConfigured({
        code: '503',
        message: registryProse,
        status: 503,
        details: { reason: SERVICE_NOT_CONFIGURED, service: 'compute' },
      })
    ).toBe(true);
  });

  it('rejects the same message text under a non-503 status', () => {
    // A 500 whose message happens to contain the registry prose is a
    // backend failure, not an absent service.
    expect(
      isServiceNotConfigured({
        code: 'SERVER_ERROR',
        message: 'compute surface is dark after backend failure',
        status: 500,
        details: { reason: SERVICE_NOT_CONFIGURED },
      })
    ).toBe(false);
  });

  it('rejects an unrelated 503 that carries no discriminator', () => {
    expect(
      isServiceNotConfigured({
        code: 'SERVER_ERROR',
        message: 'compute backend temporarily unavailable',
        status: 503,
      })
    ).toBe(false);
  });

  it('rejects a 503 whose prose matches but whose discriminator does not', () => {
    expect(
      isServiceNotConfigured({
        code: 'SERVER_ERROR',
        message: registryProse,
        status: 503,
        details: { reason: 'UPSTREAM_TIMEOUT' },
      })
    ).toBe(false);
  });

  it('rejects a 503 with no details at all', () => {
    expect(isServiceNotConfigured({ status: 503 })).toBe(false);
  });

  it('rejects a discriminator carried without any status', () => {
    expect(
      isServiceNotConfigured({ details: { reason: SERVICE_NOT_CONFIGURED } })
    ).toBe(false);
  });

  it('rejects a status that is a 503-looking string rather than the number', () => {
    expect(
      isServiceNotConfigured({
        status: '503',
        details: { reason: SERVICE_NOT_CONFIGURED },
      })
    ).toBe(false);
  });

  it('rejects null, undefined and non-object errors', () => {
    expect(isServiceNotConfigured(null)).toBe(false);
    expect(isServiceNotConfigured(undefined)).toBe(false);
    expect(isServiceNotConfigured('service not configured by daemon')).toBe(false);
    expect(isServiceNotConfigured(503)).toBe(false);
  });

  it('accepts an ApiError-shaped instance, not just a plain object', () => {
    class FakeApiError extends Error {
      status = 503;
      details = { reason: SERVICE_NOT_CONFIGURED, service: 'switch' };
    }
    expect(isServiceNotConfigured(new FakeApiError(registryProse))).toBe(true);
  });
});
