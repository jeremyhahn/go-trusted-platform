import { FullConfig } from '@playwright/test';

/**
 * Global teardown for integration tests
 *
 * This runs once after all tests. Use it to:
 * - Clean up test data
 * - Close database connections
 * - Remove temporary files
 */
async function globalTeardown(config: FullConfig): Promise<void> {
  console.log('\n[Global Teardown] Starting cleanup...');

  // Clean up test artifacts if needed
  // For now, we let Playwright handle artifact cleanup

  console.log('[Global Teardown] Cleanup complete\n');
}

export default globalTeardown;
