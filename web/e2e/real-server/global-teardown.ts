import { e2ePort, stopServer } from './global-setup';

/**
 * Real-server Playwright global teardown (#2034): stops the platformd that
 * global-setup.ts started and removes its temporary directory (kept when
 * E2E_KEEP_DATA is set).
 */
async function globalTeardown(): Promise<void> {
  await stopServer(e2ePort());
}

export default globalTeardown;
