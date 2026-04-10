/**
 * Platform Context and Provider
 *
 * React context for providing PlatformClient to the component tree.
 *
 * @packageDocumentation
 */

import React from 'react';
import { PlatformClient } from '../client/platform-client.js';
import type { PlatformClientConfig } from '../client/platform-client.js';

/**
 * Value provided by the PlatformContext
 */
export interface PlatformContextValue {
  /** The PlatformClient instance */
  client: PlatformClient;
}

/**
 * React Context for the Platform client
 *
 * @internal
 */
export const PlatformContext = React.createContext<PlatformContextValue | null>(null);

// Display name for React DevTools
PlatformContext.displayName = 'PlatformContext';

/**
 * Props for the PlatformProvider component
 */
export interface PlatformProviderProps {
  /** Child components that will have access to the client */
  children: React.ReactNode;

  /**
   * Configuration for creating a new PlatformClient.
   * Ignored if `client` is provided.
   */
  config?: PlatformClientConfig;

  /**
   * Pre-configured PlatformClient instance.
   * When provided, `config` is ignored.
   */
  client?: PlatformClient;
}

/**
 * Provider component for the Platform context
 *
 * Provides a PlatformClient instance to all child components.
 * You can either provide a pre-configured client or configuration to create one.
 *
 * @example
 * ```tsx
 * // Using configuration
 * function App() {
 *   return (
 *     <PlatformProvider config={{ baseUrl: 'https://api.example.com' }}>
 *       <MyComponent />
 *     </PlatformProvider>
 *   );
 * }
 *
 * // Using pre-configured client
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * function App() {
 *   return (
 *     <PlatformProvider client={client}>
 *       <MyComponent />
 *     </PlatformProvider>
 *   );
 * }
 * ```
 */
export function PlatformProvider({
  children,
  config,
  client,
}: PlatformProviderProps): React.JSX.Element {
  // Memoize the client instance to prevent unnecessary re-renders
  // Only create a new client if the config or client prop changes
  const platformClient = React.useMemo(() => {
    if (client !== undefined) {
      return client;
    }
    return new PlatformClient(config);
  }, [client, config]);

  const contextValue = React.useMemo<PlatformContextValue>(
    () => ({ client: platformClient }),
    [platformClient]
  );

  return (
    <PlatformContext.Provider value={contextValue}>
      {children}
    </PlatformContext.Provider>
  );
}

/**
 * Hook to access the PlatformClient from context
 *
 * Must be used within a PlatformProvider.
 *
 * @returns The PlatformClient instance
 * @throws Error if used outside of a PlatformProvider
 *
 * @example
 * ```tsx
 * function MyComponent() {
 *   const client = usePlatformClient();
 *
 *   const handleClick = async () => {
 *     const response = await client.platform.getHealth();
 *     console.log(response.data);
 *   };
 *
 *   return <button onClick={handleClick}>Check Health</button>;
 * }
 * ```
 */
export function usePlatformClient(): PlatformClient {
  const context = React.useContext(PlatformContext);

  if (context === null) {
    throw new Error(
      'usePlatformClient must be used within a PlatformProvider. ' +
        'Wrap your component tree with <PlatformProvider>.'
    );
  }

  return context.client;
}

/**
 * Hook to optionally access the PlatformClient from context
 *
 * Returns null if not within a PlatformProvider instead of throwing.
 * Useful for components that may be used both inside and outside a provider.
 *
 * @returns The PlatformClient instance or null if not available
 *
 * @example
 * ```tsx
 * function MyComponent() {
 *   const client = usePlatformClientOptional();
 *
 *   if (client === null) {
 *     return <div>No client available</div>;
 *   }
 *
 *   // ... use client
 * }
 * ```
 */
export function usePlatformClientOptional(): PlatformClient | null {
  const context = React.useContext(PlatformContext);
  return context?.client ?? null;
}
