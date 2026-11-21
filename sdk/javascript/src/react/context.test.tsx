/**
 * Unit tests for the React provider context (#1805).
 *
 * The package carries no renderer (no react-dom), so the hooks run under a
 * minimal stand-in for React's dispatcher: `React.useContext` reads the
 * context's current value (the default when no provider wraps the call, or
 * the value a test supplies) and `React.useMemo` runs its factory and
 * records the dependency list.
 */

import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { PlatformClient } from '../client/platform-client.js';
import {
  PlatformContext,
  PlatformProvider,
  usePlatformClient,
  usePlatformClientOptional,
} from './context.js';
import type { PlatformContextValue } from './context.js';

type ContextInternals = { _currentValue: PlatformContextValue | null };

/** Resolve useContext as React does with no provider above the caller. */
function withoutProvider(): void {
  vi.spyOn(React, 'useContext').mockImplementation(
    (ctx) => (ctx as unknown as ContextInternals)._currentValue
  );
}

/** Resolve useContext to the given value, as a provider above the caller would. */
function withValue(value: PlatformContextValue | null): void {
  vi.spyOn(React, 'useContext').mockImplementation((ctx) => {
    expect(ctx).toBe(PlatformContext);
    return value;
  });
}

/** Run every useMemo factory and record the dependency lists in call order. */
function recordMemo(): unknown[][] {
  const deps: unknown[][] = [];
  vi.spyOn(React, 'useMemo').mockImplementation((factory, d) => {
    deps.push([...(d ?? [])]);
    return factory();
  });
  return deps;
}

type ProviderElement = React.ReactElement<{
  value: PlatformContextValue;
  children?: React.ReactNode;
}>;

afterEach(() => {
  vi.restoreAllMocks();
});

describe('PlatformContext', () => {
  it('is a React context whose default value is null', () => {
    expect(PlatformContext.Provider).toBeDefined();
    expect(PlatformContext.Consumer).toBeDefined();
    expect((PlatformContext as unknown as ContextInternals)._currentValue).toBeNull();
  });
});

describe('PlatformProvider', () => {
  it('provides the client it is given and does not build another', () => {
    const deps = recordMemo();
    const client = new PlatformClient();
    const config = {};
    const child = React.createElement('span', null, 'x');

    const el = PlatformProvider({ client, config, children: child }) as ProviderElement;

    expect(el.type).toBe(PlatformContext.Provider);
    expect(el.props.value.client).toBe(client);
    expect(el.props.children).toBe(child);
    expect(deps[0]).toEqual([client, config]);
    expect(deps[1]).toEqual([client]);
  });

  it('builds a PlatformClient from the config when no client is given', () => {
    recordMemo();
    const el = PlatformProvider({ config: {}, children: null }) as ProviderElement;

    expect(el.type).toBe(PlatformContext.Provider);
    expect(el.props.value.client).toBeInstanceOf(PlatformClient);
    expect(el.props.children).toBeNull();
  });

  it('builds a default PlatformClient when neither config nor client is given', () => {
    recordMemo();
    const el = PlatformProvider({ children: 'text' }) as ProviderElement;

    expect(el.props.value.client).toBeInstanceOf(PlatformClient);
    expect(el.props.children).toBe('text');
  });

  it('treats an explicit undefined client as absent', () => {
    recordMemo();
    const el = PlatformProvider({
      client: undefined,
      children: null,
    } as unknown as Parameters<typeof PlatformProvider>[0]) as ProviderElement;

    expect(el.props.value.client).toBeInstanceOf(PlatformClient);
  });

  it('builds a new client for each render that is not memoised', () => {
    recordMemo();
    const a = PlatformProvider({ children: null }) as ProviderElement;
    const b = PlatformProvider({ children: null }) as ProviderElement;

    expect(a.props.value.client).not.toBe(b.props.value.client);
  });
});

describe('usePlatformClient', () => {
  it('returns the client from the nearest provider', () => {
    const client = new PlatformClient();
    withValue({ client });

    expect(usePlatformClient()).toBe(client);
  });

  it('throws outside a PlatformProvider', () => {
    withoutProvider();

    expect(() => usePlatformClient()).toThrowError(
      /usePlatformClient must be used within a PlatformProvider/
    );
  });

  it('names the fix in its error message', () => {
    withValue(null);

    expect(() => usePlatformClient()).toThrowError(/Wrap your component tree with <PlatformProvider>/);
  });
});

describe('usePlatformClientOptional', () => {
  it('returns the client from the nearest provider', () => {
    const client = new PlatformClient();
    withValue({ client });

    expect(usePlatformClientOptional()).toBe(client);
  });

  it('returns null outside a PlatformProvider instead of throwing', () => {
    withoutProvider();

    expect(usePlatformClientOptional()).toBeNull();
  });

  it('returns null when the context value carries no client', () => {
    withValue({ client: undefined } as unknown as PlatformContextValue);

    expect(usePlatformClientOptional()).toBeNull();
  });
});
