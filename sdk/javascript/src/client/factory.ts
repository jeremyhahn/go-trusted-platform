/**
 * Factory for creating platform clients with automatic environment detection.
 * In Wails desktop mode, uses IPC bindings. In browser/Node, uses REST API.
 */

import { PlatformClient } from './platform-client.js';
import type { WailsPlatformClient } from './wails-client.js';

/**
 * Detects whether the current runtime is inside a Wails desktop application
 * by checking for the presence of the Wails-generated `window.go` namespace.
 */
function isWailsRuntime(): boolean {
  return (
    typeof window !== 'undefined' &&
    typeof (window as unknown as Record<string, unknown>).go !== 'undefined'
  );
}

/**
 * Returns true when running inside a Wails desktop context.
 */
export function isDesktop(): boolean {
  return isWailsRuntime();
}

/** Configuration options for getClient. */
export interface ClientConfig {
  /** Base URL for the REST API (ignored in desktop mode). */
  readonly baseUrl?: string;
}

/**
 * Creates a PlatformClient appropriate for the current environment.
 * In desktop (Wails) mode, returns a WailsPlatformClient.
 * In browser mode, returns a standard PlatformClient using REST.
 */
export async function getClient(
  config?: ClientConfig,
): Promise<PlatformClient | WailsPlatformClient> {
  if (isWailsRuntime()) {
    const { WailsPlatformClient: WailsClient } = await import('./wails-client.js');
    return new WailsClient();
  }
  // Leave an unset baseUrl to resolveConfig's default: an empty string
  // fails validateConfig, so getClient() with no config used to throw.
  return config?.baseUrl !== undefined
    ? new PlatformClient({ baseUrl: config.baseUrl })
    : new PlatformClient();
}
