import { FullConfig } from '@playwright/test';
import https from 'https';

// Allow self-signed certificates for backend health checks
const agent = new https.Agent({ rejectUnauthorized: false });

/** Fetch with self-signed cert support for HTTPS URLs. */
async function safeFetch(url: string): Promise<{ ok: boolean; status: number }> {
  // For HTTPS with self-signed certs, use Node https.get
  if (url.startsWith('https://')) {
    return new Promise((resolve) => {
      const req = https.get(url, { agent }, (res) => {
        resolve({ ok: (res.statusCode ?? 500) < 400, status: res.statusCode ?? 500 });
        res.resume(); // drain
      });
      req.on('error', () => resolve({ ok: false, status: 0 }));
      req.setTimeout(10000, () => { req.destroy(); resolve({ ok: false, status: 0 }); });
    });
  }
  const res = await fetch(url);
  return { ok: res.ok, status: res.status };
}

/**
 * Global setup for integration tests
 *
 * This runs once before all tests. Use it to:
 * - Verify backend services are running
 * - Set up test database state
 * - Create test users/credentials
 */
async function globalSetup(config: FullConfig): Promise<void> {
  console.log('\n[Global Setup] Starting integration test setup...');

  // Get the base URL from config
  const baseURL = config.projects[0]?.use?.baseURL || 'http://localhost:3000';
  const backendURL = process.env.BACKEND_URL || 'https://localhost:8443';

  // Verify frontend is accessible
  console.log(`[Global Setup] Checking frontend at ${baseURL}...`);
  try {
    const response = await safeFetch(baseURL);
    if (response.ok) {
      console.log('[Global Setup] Frontend is accessible');
    } else {
      console.warn(`[Global Setup] Frontend returned status ${response.status}`);
    }
  } catch (error) {
    console.warn('[Global Setup] Frontend check failed:', error);
    console.warn('[Global Setup] Tests may fail if frontend is not running');
  }

  // Verify backend health
  console.log(`[Global Setup] Checking backend at ${backendURL}...`);
  try {
    const response = await safeFetch(`${backendURL}/api/v1/status`);
    if (response.ok) {
      console.log('[Global Setup] Backend is healthy');
    } else {
      console.warn(`[Global Setup] Backend returned status ${response.status}`);
    }
  } catch (error) {
    console.warn('[Global Setup] Backend health check failed:', error);
    console.warn('[Global Setup] Some tests may be skipped if backend is unavailable');
  }

  // Store test context in environment
  process.env.TEST_BACKEND_URL = backendURL;
  process.env.TEST_FRONTEND_URL = baseURL;

  console.log('[Global Setup] Setup complete\n');
}

export default globalSetup;
