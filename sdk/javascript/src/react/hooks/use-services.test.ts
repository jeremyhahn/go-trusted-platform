/**
 * Unit tests for the per-service React hooks (#1805).
 *
 * Each hook reads the client from the nearest PlatformProvider and returns
 * one of its services. The package carries no renderer (no react-dom), so
 * `React.useContext` is stood in for: it returns the value a provider would
 * supply, or the context's default (null) when no provider wraps the call.
 */

import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { PlatformClient } from '../../client/platform-client.js';
import { PlatformContext } from '../context.js';
import type { PlatformContextValue } from '../context.js';
import {
  useAttestation,
  useCA,
  useCompute,
  useDevice,
  useDNS,
  useGateway,
  useIAM,
  useIDevID,
  useKMS,
  useOverlay,
  usePlatform,
  usePXE,
  useSDN,
  useTenant,
  useTPM,
  useVPN,
  useVTPM,
} from './use-services.js';

type ContextInternals = { _currentValue: PlatformContextValue | null };

function withClient(client: PlatformClient): void {
  vi.spyOn(React, 'useContext').mockImplementation((ctx) => {
    expect(ctx).toBe(PlatformContext);
    return { client };
  });
}

function withoutProvider(): void {
  vi.spyOn(React, 'useContext').mockImplementation(
    (ctx) => (ctx as unknown as ContextInternals)._currentValue
  );
}

const hooks: Array<[string, () => unknown, keyof PlatformClient]> = [
  ['useAttestation', useAttestation, 'attestation'],
  ['useCA', useCA, 'ca'],
  ['useCompute', useCompute, 'compute'],
  ['useDevice', useDevice, 'device'],
  ['useDNS', useDNS, 'dns'],
  ['useGateway', useGateway, 'gateway'],
  ['useIAM', useIAM, 'iam'],
  ['useIDevID', useIDevID, 'idevid'],
  ['useKMS', useKMS, 'kms'],
  ['useOverlay', useOverlay, 'overlay'],
  ['usePlatform', usePlatform, 'platform'],
  ['usePXE', usePXE, 'pxe'],
  ['useSDN', useSDN, 'sdn'],
  ['useTenant', useTenant, 'tenant'],
  ['useTPM', useTPM, 'tpm'],
  ['useVTPM', useVTPM, 'vtpm'],
  ['useVPN', useVPN, 'vpn'],
];

afterEach(() => {
  vi.restoreAllMocks();
});

describe('use-services hooks', () => {
  it('covers one hook per service, each on a distinct client property', () => {
    expect(hooks).toHaveLength(17);
    expect(new Set(hooks.map(([, , prop]) => prop)).size).toBe(hooks.length);
  });

  describe.each(hooks)('%s', (name, hook, prop) => {
    it(`returns client.${String(prop)} from the provider`, () => {
      const client = new PlatformClient();
      withClient(client);

      const service = hook();

      expect(service).toBeDefined();
      expect(service).toBe(client[prop]);
    });

    it('returns the same service instance on every call with the same client', () => {
      const client = new PlatformClient();
      withClient(client);

      expect(hook()).toBe(hook());
    });

    it('follows the provider when the client changes', () => {
      const a = new PlatformClient();
      const b = new PlatformClient();
      const spy = vi.spyOn(React, 'useContext');
      spy.mockReturnValueOnce({ client: a }).mockReturnValueOnce({ client: b });

      const first = hook();
      const second = hook();

      expect(first).toBe(a[prop]);
      expect(second).toBe(b[prop]);
      expect(first).not.toBe(second);
    });

    it('throws outside a PlatformProvider', () => {
      withoutProvider();

      expect(() => hook()).toThrowError(
        /usePlatformClient must be used within a PlatformProvider/
      );
    });

    it(`throws when the provided value is null (${name})`, () => {
      vi.spyOn(React, 'useContext').mockReturnValue(null);

      expect(() => hook()).toThrowError(/PlatformProvider/);
    });
  });
});
