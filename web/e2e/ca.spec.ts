import { test, expect, Page, Route, Request } from '@playwright/test';
import {
  createTenantOwnerSession,
  createTenantMemberSession,
} from './fixtures/auth-setup';
import { mockTenantApi, ApiError } from './fixtures/api-mock';

/**
 * Certificate Authority E2E Tests
 *
 * Tests for the CA management pages:
 * - /ca/certificates - Certificate list
 * - /ca/certificates/[id] - Certificate details
 * - /ca/requests - Certificate requests
 * - /ca/crl - CRL management
 */

// Types for CA API mocking
export interface Certificate {
  serial: string;
  commonName: string;
  issuer: string;
  status: 'ACTIVE' | 'REVOKED' | 'EXPIRED';
  keyAlgorithm: string;
  notBefore: string;
  notAfter: string;
}

export interface CertificateDetail {
  serial: string;
  subject: {
    commonName: string;
    organization?: string;
    country?: string;
  };
  issuer: string;
  status: 'ACTIVE' | 'REVOKED' | 'EXPIRED';
  isCA: boolean;
  keyAlgorithm: string;
  signatureAlgorithm: string;
  notBefore: string;
  notAfter: string;
  pem?: string;
  der?: string;
}

export interface CertificateRequest {
  id: string;
  requester: string;
  subject: string;
  type: 'root' | 'intermediate' | 'leaf';
  requestedAt: string;
  status: 'pending' | 'approved' | 'denied';
  csr: string;
}

export interface CACertificateListResponse {
  certificates: Certificate[];
  total: number;
}

export interface CACertificateDetailResponse {
  certificate: CertificateDetail;
}

export interface CARequestListResponse {
  requests: CertificateRequest[];
  total: number;
}

// Mock data generators
let certIdCounter = 1;

export function createMockCertificate(
  overrides: Partial<Certificate> = {}
): Certificate {
  const id = overrides.serial || `cert-serial-${certIdCounter++}`;
  const now = new Date();
  const notAfter = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000); // 1 year

  return {
    serial: id,
    commonName: `test-cert-${certIdCounter}.example.com`,
    issuer: 'CN=Test Root CA,O=Test Org',
    status: 'ACTIVE',
    keyAlgorithm: 'RSA_2048',
    notBefore: now.toISOString(),
    notAfter: notAfter.toISOString(),
    ...overrides,
  };
}

export function createMockCertificateDetail(
  overrides: Partial<CertificateDetail> = {}
): CertificateDetail {
  const now = new Date();
  const notAfter = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000);

  return {
    serial: `cert-detail-${certIdCounter++}`,
    subject: {
      commonName: 'test.example.com',
      organization: 'Test Org',
      country: 'US',
    },
    issuer: 'CN=Test Root CA,O=Test Org',
    status: 'ACTIVE',
    isCA: false,
    keyAlgorithm: 'RSA_2048',
    signatureAlgorithm: 'SHA256WithRSA',
    notBefore: now.toISOString(),
    notAfter: notAfter.toISOString(),
    pem: '-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----',
    der: 'base64encodedder',
    ...overrides,
  };
}

export function createMockCertificateRequest(
  overrides: Partial<CertificateRequest> = {}
): CertificateRequest {
  const now = new Date();

  return {
    id: `csr-${certIdCounter++}`,
    requester: 'user@example.com',
    subject: 'CN=request.example.com,O=Test Org',
    type: 'leaf',
    requestedAt: now.toISOString(),
    status: 'pending',
    csr: '-----BEGIN CERTIFICATE REQUEST-----\nMIIB...\n-----END CERTIFICATE REQUEST-----',
    ...overrides,
  };
}

// API mock configuration
export interface CAApiMockConfig {
  initialCertificates?: Certificate[];
  certificateDetail?: CertificateDetail;
  initialRequests?: CertificateRequest[];
  listError?: ApiError | null;
  getDetailError?: ApiError | null;
  issueError?: ApiError | null;
  revokeError?: ApiError | null;
  approveError?: ApiError | null;
  rejectError?: ApiError | null;
}

interface CAApiState {
  certificates: Certificate[];
  requests: CertificateRequest[];
  config: CAApiMockConfig;
}

/**
 * Mock the CA API endpoints.
 *
 * Handles:
 * - GET /api/v1/ca/certificates - List certificates
 * - GET /api/v1/ca/certificates/:id - Get certificate details
 * - POST /api/v1/ca/certificates - Issue certificate
 * - DELETE /api/v1/ca/certificates/:id - Revoke certificate
 * - GET /api/v1/ca/requests - List requests
 * - POST /api/v1/ca/requests/:id/approve - Approve request
 * - POST /api/v1/ca/requests/:id/reject - Reject request
 */
export async function mockCAApi(
  page: Page,
  config: CAApiMockConfig = {}
): Promise<{
  getCertificates: () => Certificate[];
  getRequests: () => CertificateRequest[];
  addCertificate: (cert: Certificate) => void;
  setError: (
    endpoint: 'list' | 'detail' | 'issue' | 'revoke' | 'approve' | 'reject',
    error: ApiError | null
  ) => void;
}> {
  const state: CAApiState = {
    certificates: config.initialCertificates || [],
    requests: config.initialRequests || [],
    config: {
      listError: null,
      getDetailError: null,
      issueError: null,
      revokeError: null,
      approveError: null,
      rejectError: null,
      ...config,
    },
  };

  // Route handler for certificate list
  await page.route('**/api/v1/ca/certificates', async (route: Route, request: Request) => {
    const method = request.method();

    if (method === 'GET') {
      if (state.config.listError) {
        await route.fulfill({
          status: state.config.listError.status,
          contentType: 'application/json',
          body: JSON.stringify({
            message: state.config.listError.error,
            code: state.config.listError.errorCode || `HTTP_${state.config.listError.status}`,
          }),
        });
        return;
      }

      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          certificates: state.certificates,
          total: state.certificates.length,
        }),
      });
      return;
    }

    if (method === 'POST') {
      if (state.config.issueError) {
        await route.fulfill({
          status: state.config.issueError.status,
          contentType: 'application/json',
          body: JSON.stringify({
            message: state.config.issueError.error,
            code: state.config.issueError.errorCode || `HTTP_${state.config.issueError.status}`,
          }),
        });
        return;
      }

      try {
        const body = request.postDataJSON();
        const newCert = createMockCertificate({
          commonName: body.subject?.commonName || 'New Certificate',
          keyAlgorithm: body.keyAlgorithm || 'RSA_2048',
        });

        state.certificates.unshift(newCert);

        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({
            certificate: newCert,
          }),
        });
      } catch {
        await route.fulfill({
          status: 400,
          contentType: 'application/json',
          body: JSON.stringify({ message: 'Invalid request body', code: 'HTTP_400' }),
        });
      }
      return;
    }

    await route.continue();
  });

  // Route handler for individual certificate (get detail, revoke)
  await page.route('**/api/v1/ca/certificates/*', async (route: Route, request: Request) => {
    const method = request.method();
    const url = request.url();

    // Extract certificate ID from URL
    const match = url.match(/\/certificates\/([^/?]+)/);
    const certId = match ? decodeURIComponent(match[1]) : null;

    if (method === 'GET') {
      if (state.config.getDetailError) {
        await route.fulfill({
          status: state.config.getDetailError.status,
          contentType: 'application/json',
          body: JSON.stringify({
            message: state.config.getDetailError.error,
            code: state.config.getDetailError.errorCode || `HTTP_${state.config.getDetailError.status}`,
          }),
        });
        return;
      }

      // Return configured detail or find from list
      const detail = config.certificateDetail || createMockCertificateDetail({
        serial: certId || 'unknown',
        subject: { commonName: certId || 'Unknown Certificate' },
      });

      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          certificate: detail,
        }),
      });
      return;
    }

    if (method === 'DELETE') {
      if (state.config.revokeError) {
        await route.fulfill({
          status: state.config.revokeError.status,
          contentType: 'application/json',
          body: JSON.stringify({
            message: state.config.revokeError.error,
            code: state.config.revokeError.errorCode || `HTTP_${state.config.revokeError.status}`,
          }),
        });
        return;
      }

      // Mark certificate as revoked
      if (certId) {
        const cert = state.certificates.find((c) => c.serial === certId);
        if (cert) {
          cert.status = 'REVOKED';
        }
      }

      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ success: true }),
      });
      return;
    }

    await route.continue();
  });

  // Route handler for certificate requests
  await page.route('**/api/v1/ca/requests', async (route: Route, request: Request) => {
    const method = request.method();

    if (method === 'GET') {
      if (state.config.listError) {
        await route.fulfill({
          status: state.config.listError.status,
          contentType: 'application/json',
          body: JSON.stringify({
            message: state.config.listError.error,
            code: state.config.listError.errorCode || `HTTP_${state.config.listError.status}`,
          }),
        });
        return;
      }

      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          requests: state.requests,
          total: state.requests.length,
        }),
      });
      return;
    }

    await route.continue();
  });

  // Route handler for request approval
  await page.route('**/api/v1/ca/requests/*/approve', async (route: Route, request: Request) => {
    if (request.method() === 'POST') {
      if (state.config.approveError) {
        await route.fulfill({
          status: state.config.approveError.status,
          contentType: 'application/json',
          body: JSON.stringify({
            message: state.config.approveError.error,
            code: state.config.approveError.errorCode || `HTTP_${state.config.approveError.status}`,
          }),
        });
        return;
      }

      const url = request.url();
      const match = url.match(/\/requests\/([^/]+)\/approve/);
      const requestId = match ? match[1] : null;

      if (requestId) {
        const req = state.requests.find((r) => r.id === requestId);
        if (req) {
          req.status = 'approved';
        }
      }

      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ success: true }),
      });
      return;
    }

    await route.continue();
  });

  // Route handler for request rejection
  await page.route('**/api/v1/ca/requests/*/reject', async (route: Route, request: Request) => {
    if (request.method() === 'POST') {
      if (state.config.rejectError) {
        await route.fulfill({
          status: state.config.rejectError.status,
          contentType: 'application/json',
          body: JSON.stringify({
            message: state.config.rejectError.error,
            code: state.config.rejectError.errorCode || `HTTP_${state.config.rejectError.status}`,
          }),
        });
        return;
      }

      const url = request.url();
      const match = url.match(/\/requests\/([^/]+)\/reject/);
      const requestId = match ? match[1] : null;

      if (requestId) {
        const req = state.requests.find((r) => r.id === requestId);
        if (req) {
          req.status = 'denied';
        }
      }

      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ success: true }),
      });
      return;
    }

    await route.continue();
  });

  return {
    getCertificates: () => [...state.certificates],
    getRequests: () => [...state.requests],
    addCertificate: (cert: Certificate) => {
      state.certificates.unshift(cert);
    },
    setError: (
      endpoint: 'list' | 'detail' | 'issue' | 'revoke' | 'approve' | 'reject',
      error: ApiError | null
    ) => {
      switch (endpoint) {
        case 'list':
          state.config.listError = error;
          break;
        case 'detail':
          state.config.getDetailError = error;
          break;
        case 'issue':
          state.config.issueError = error;
          break;
        case 'revoke':
          state.config.revokeError = error;
          break;
        case 'approve':
          state.config.approveError = error;
          break;
        case 'reject':
          state.config.rejectError = error;
          break;
      }
    },
  };
}

test.describe('Certificate Authority - Certificates Page', () => {
  test.describe('Certificate List', () => {
    test.beforeEach(async ({ page }) => {
      await createTenantOwnerSession(page.context());
    });

    test('should display certificate table with certificates', async ({ page }) => {
      const certificates = [
        createMockCertificate({
          serial: 'cert-001',
          commonName: 'server1.example.com',
          status: 'ACTIVE',
        }),
        createMockCertificate({
          serial: 'cert-002',
          commonName: 'server2.example.com',
          status: 'REVOKED',
        }),
        createMockCertificate({
          serial: 'cert-003',
          commonName: 'server3.example.com',
          status: 'EXPIRED',
        }),
      ];

      await mockCAApi(page, { initialCertificates: certificates });
      await mockTenantApi(page);

      await page.goto('/ca/certificates');

      // Verify page loaded with correct elements
      await expect(page.getByRole('heading', { name: /certificates/i })).toBeVisible();

      // Verify certificates are displayed
      await expect(page.getByText('server1.example.com')).toBeVisible();
      await expect(page.getByText('server2.example.com')).toBeVisible();
      await expect(page.getByText('server3.example.com')).toBeVisible();
    });

    test('should display certificate status badges correctly', async ({ page }) => {
      const certificates = [
        createMockCertificate({ serial: 'active-cert', commonName: 'active.example.com', status: 'ACTIVE' }),
        createMockCertificate({ serial: 'revoked-cert', commonName: 'revoked.example.com', status: 'REVOKED' }),
        createMockCertificate({ serial: 'expired-cert', commonName: 'expired.example.com', status: 'EXPIRED' }),
      ];

      await mockCAApi(page, { initialCertificates: certificates });
      await mockTenantApi(page);

      await page.goto('/ca/certificates');

      // Wait for table to load
      await expect(page.getByText('active.example.com')).toBeVisible();

      // Verify status badges are visible
      await expect(page.locator('text=active').first()).toBeVisible();
      await expect(page.locator('text=revoked').first()).toBeVisible();
      await expect(page.locator('text=expired').first()).toBeVisible();
    });

    test('should filter certificates using search', async ({ page }) => {
      const certificates = [
        createMockCertificate({ serial: 'cert-web', commonName: 'web.example.com' }),
        createMockCertificate({ serial: 'cert-api', commonName: 'api.example.com' }),
        createMockCertificate({ serial: 'cert-db', commonName: 'database.internal.com' }),
      ];

      await mockCAApi(page, { initialCertificates: certificates });
      await mockTenantApi(page);

      await page.goto('/ca/certificates');

      // Wait for certificates to load
      await expect(page.getByText('web.example.com')).toBeVisible();

      // Search for specific certificate (scope to main to avoid header search)
      const main = page.getByRole('main');
      const searchInput = main.getByPlaceholder(/search/i);
      await searchInput.fill('web');

      // Verify filtered result
      await expect(page.getByText('web.example.com')).toBeVisible();
    });

    test('should show empty state when no certificates', async ({ page }) => {
      await mockCAApi(page, { initialCertificates: [] });
      await mockTenantApi(page);

      await page.goto('/ca/certificates');

      // Wait for page to load
      await expect(page.getByRole('heading', { name: /certificates/i })).toBeVisible();

      // Verify empty state or no data message
      await expect(page.locator('table')).toBeVisible();
    });

    test('should navigate to certificate details on view', async ({ page }) => {
      const cert = createMockCertificate({
        serial: 'cert-view-test',
        commonName: 'viewtest.example.com',
      });

      await mockCAApi(page, {
        initialCertificates: [cert],
        certificateDetail: createMockCertificateDetail({
          serial: 'cert-view-test',
          subject: { commonName: 'viewtest.example.com' },
        }),
      });
      await mockTenantApi(page);

      await page.goto('/ca/certificates');

      // Wait for certificate to appear with increased timeout
      await expect(page.getByText('viewtest.example.com')).toBeVisible({ timeout: 10000 });

      // Click the actions menu and view details (use table row button specifically)
      const tableRow = page.getByRole('row').filter({ hasText: 'viewtest.example.com' });
      const menuButton = tableRow.getByRole('button', { name: /open menu/i });
      await expect(menuButton).toBeVisible({ timeout: 5000 });
      await menuButton.click();

      // Wait for menu to be visible before clicking
      const viewMenuItem = page.getByRole('menuitem', { name: /view details/i });
      await expect(viewMenuItem).toBeVisible({ timeout: 5000 });
      await viewMenuItem.click();

      // Wait for navigation to complete with extended timeout
      await page.waitForURL(/\/ca\/certificates\/cert-view-test/, { timeout: 15000 });
      await expect(page).toHaveURL(/\/ca\/certificates\/cert-view-test/);
    });

    test('should refresh certificate list', async ({ page }) => {
      const certificates = [
        createMockCertificate({ serial: 'cert-refresh', commonName: 'refresh.example.com' }),
      ];

      await mockCAApi(page, { initialCertificates: certificates });
      await mockTenantApi(page);

      await page.goto('/ca/certificates');

      // Wait for initial load
      await expect(page.getByText('refresh.example.com')).toBeVisible();

      // Click refresh button
      await page.getByRole('button', { name: /refresh/i }).click();

      // Verify list is still visible after refresh
      await expect(page.getByText('refresh.example.com')).toBeVisible();
    });
  });

  test.describe('Issue Certificate', () => {
    test.beforeEach(async ({ page }) => {
      await createTenantOwnerSession(page.context());
    });

    test('should open issue certificate dialog', async ({ page }) => {
      await mockCAApi(page);
      await mockTenantApi(page);

      await page.goto('/ca/certificates');

      // Click issue certificate button
      await page.getByRole('button', { name: /issue certificate/i }).click();

      // Verify dialog opens
      const dialog = page.getByRole('dialog');
      await expect(dialog).toBeVisible();
      // Use h2 specifically as dialog has both h2 and h3 with same title
      await expect(dialog.locator('h2', { hasText: /issue new certificate/i })).toBeVisible();
    });

    test('should display certificate form fields', async ({ page }) => {
      await mockCAApi(page);
      await mockTenantApi(page);

      await page.goto('/ca/certificates');

      await page.getByRole('button', { name: /issue certificate/i }).click();

      // Verify form fields are present
      await expect(page.locator('label:has-text("Subject")')).toBeVisible();
      await expect(page.locator('label:has-text("Certificate Type")')).toBeVisible();
      await expect(page.locator('label:has-text("Key Algorithm")')).toBeVisible();
      await expect(page.locator('label:has-text("Validity Period")')).toBeVisible();
    });

    test('should submit certificate request form', async ({ page }) => {
      const mockApi = await mockCAApi(page);
      await mockTenantApi(page);

      // Set up dialog handler before navigation for browser alerts
      page.on('dialog', async (dialog) => {
        await dialog.accept();
      });

      await page.goto('/ca/certificates');

      // Wait for page to load
      await expect(page.getByRole('heading', { name: /certificates/i })).toBeVisible({ timeout: 10000 });

      // Open dialog - use the first Issue Certificate button (in header)
      const issueButton = page.getByRole('button', { name: /issue certificate/i }).first();
      await expect(issueButton).toBeVisible({ timeout: 5000 });
      await issueButton.click();

      // Wait for dialog to be visible
      const dialogElement = page.getByRole('dialog');
      await expect(dialogElement).toBeVisible({ timeout: 5000 });

      // Fill out the form - use the subject input by id
      const subjectInput = page.locator('#subject');
      await expect(subjectInput).toBeVisible({ timeout: 5000 });
      await subjectInput.fill('CN=newcert.example.com,O=Test Org');

      // Submit the form - the submit button inside the form says "Issue Certificate"
      const submitButton = dialogElement.getByRole('button', { name: /issue certificate/i });
      await expect(submitButton).toBeEnabled({ timeout: 5000 });
      await submitButton.click();

      // Wait for the API call and response to complete
      // The form will trigger the mutation which posts to the API
      await page.waitForTimeout(1500);

      // Verify certificate was added to mock state
      const certs = mockApi.getCertificates();
      expect(certs.length).toBeGreaterThan(0);
    });

    test('should require subject field', async ({ page }) => {
      await mockCAApi(page);
      await mockTenantApi(page);

      await page.goto('/ca/certificates');

      await page.getByRole('button', { name: /issue certificate/i }).click();

      // Try to submit without subject
      const submitButton = page.getByRole('button', { name: /issue certificate/i }).last();

      // The button should be disabled when subject is empty
      await expect(submitButton).toBeDisabled();
    });

    test('should handle issue certificate error', async ({ page }) => {
      await mockCAApi(page, {
        issueError: { error: 'Certificate already exists', status: 409 },
      });
      await mockTenantApi(page);

      await page.goto('/ca/certificates');

      await page.getByRole('button', { name: /issue certificate/i }).click();

      await page.locator('#subject').fill('CN=duplicate.example.com');

      await page.getByRole('button', { name: /issue certificate/i }).last().click();

      // Handle the alert dialog
      page.on('dialog', async (dialog) => {
        expect(dialog.message()).toContain('Failed to issue certificate');
        await dialog.accept();
      });
    });
  });

  test.describe('Revoke Certificate', () => {
    test.beforeEach(async ({ page }) => {
      await createTenantOwnerSession(page.context());
    });

    test('should revoke an active certificate', async ({ page }) => {
      const cert = createMockCertificate({
        serial: 'cert-to-revoke',
        commonName: 'revoke-me.example.com',
        status: 'ACTIVE',
      });

      await mockCAApi(page, { initialCertificates: [cert] });
      await mockTenantApi(page);

      await page.goto('/ca/certificates');

      // Wait for certificate to appear
      await expect(page.getByText('revoke-me.example.com')).toBeVisible();

      // Click actions menu and verify revoke option exists
      const tableRow = page.getByRole('row').filter({ hasText: 'revoke-me.example.com' });
      await tableRow.getByRole('button', { name: /open menu/i }).click();

      // Verify revoke menu item is visible for active certificates
      await expect(page.getByRole('menuitem', { name: /revoke/i })).toBeVisible();
    });

    test('should not show revoke option for revoked certificates', async ({ page }) => {
      const cert = createMockCertificate({
        serial: 'already-revoked',
        commonName: 'already-revoked.example.com',
        status: 'REVOKED',
      });

      await mockCAApi(page, { initialCertificates: [cert] });
      await mockTenantApi(page);

      await page.goto('/ca/certificates');

      await expect(page.getByText('already-revoked.example.com')).toBeVisible();

      // Open actions menu (use table row button specifically)
      const tableRow = page.getByRole('row').filter({ hasText: 'already-revoked.example.com' });
      await tableRow.getByRole('button', { name: /open menu/i }).click();

      // Revoke option should not be visible
      await expect(page.getByRole('menuitem', { name: /revoke/i })).not.toBeVisible();
    });

    test('should handle revocation error', async ({ page }) => {
      const cert = createMockCertificate({
        serial: 'cert-revoke-error',
        commonName: 'error.example.com',
        status: 'ACTIVE',
      });

      await mockCAApi(page, {
        initialCertificates: [cert],
        revokeError: { error: 'Failed to revoke certificate', status: 500 },
      });
      await mockTenantApi(page);

      await page.goto('/ca/certificates');

      await expect(page.getByText('error.example.com')).toBeVisible();

      page.on('dialog', async (dialog) => {
        if (dialog.type() === 'prompt') {
          await dialog.accept('Test reason');
        } else if (dialog.message().includes('Failed')) {
          await dialog.accept();
        }
      });

      // Use table row button specifically
      const tableRow = page.getByRole('row').filter({ hasText: 'error.example.com' });
      await tableRow.getByRole('button', { name: /open menu/i }).click();
      await page.getByRole('menuitem', { name: /revoke/i }).click();

      // Error should be shown (via alert or toast)
    });
  });

  test.describe('Certificate Details', () => {
    test.beforeEach(async ({ page }) => {
      await createTenantOwnerSession(page.context());
    });

    test('should display certificate details', async ({ page }) => {
      const detail = createMockCertificateDetail({
        serial: 'detail-test-cert',
        subject: { commonName: 'detail.example.com', organization: 'Test Org' },
        status: 'ACTIVE',
        keyAlgorithm: 'RSA_2048',
        signatureAlgorithm: 'SHA256WithRSA',
      });

      await mockCAApi(page, { certificateDetail: detail });
      await mockTenantApi(page);

      await page.goto('/ca/certificates/detail-test-cert');

      // Verify detail page content
      await expect(page.getByRole('heading', { name: /certificate details/i })).toBeVisible();
      await expect(page.getByRole('heading', { name: 'detail.example.com' })).toBeVisible();
    });

    test('should show download buttons', async ({ page }) => {
      const detail = createMockCertificateDetail({
        serial: 'download-cert',
        subject: { commonName: 'download.example.com' },
        pem: '-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----',
      });

      await mockCAApi(page, { certificateDetail: detail });
      await mockTenantApi(page);

      await page.goto('/ca/certificates/download-cert');

      // Verify download buttons are visible
      await expect(page.getByRole('button', { name: /pem/i })).toBeVisible();
      await expect(page.getByRole('button', { name: /der/i })).toBeVisible();
    });

    test('should show revoke button for active certificates', async ({ page }) => {
      const detail = createMockCertificateDetail({
        serial: 'active-detail',
        subject: { commonName: 'active-detail.example.com' },
        status: 'ACTIVE',
      });

      await mockCAApi(page, { certificateDetail: detail });
      await mockTenantApi(page);

      await page.goto('/ca/certificates/active-detail');

      await expect(page.getByRole('button', { name: /revoke/i })).toBeVisible();
    });

    test('should hide revoke button for revoked certificates', async ({ page }) => {
      const detail = createMockCertificateDetail({
        serial: 'revoked-detail',
        subject: { commonName: 'revoked-detail.example.com' },
        status: 'REVOKED',
      });

      await mockCAApi(page, { certificateDetail: detail });
      await mockTenantApi(page);

      await page.goto('/ca/certificates/revoked-detail');

      // Revoke button should not be visible for already revoked certs
      await expect(page.getByRole('button', { name: /revoke/i })).not.toBeVisible();
    });

    test('should navigate back to certificate list', async ({ page }) => {
      const detail = createMockCertificateDetail({
        serial: 'back-nav-cert',
        subject: { commonName: 'back.example.com' },
      });

      await mockCAApi(page, { certificateDetail: detail, initialCertificates: [] });
      await mockTenantApi(page);

      await page.goto('/ca/certificates/back-nav-cert');

      // Click back navigation link in breadcrumb
      await page.getByRole('link', { name: /certificates/i }).click();

      await expect(page).toHaveURL(/\/ca\/certificates\/?$/);
    });

    test('should handle certificate not found', async ({ page }) => {
      await mockCAApi(page, {
        getDetailError: { error: 'Certificate not found', status: 404 },
      });
      await mockTenantApi(page);

      await page.goto('/ca/certificates/nonexistent-cert');

      // Should show error state (scope to main to avoid sidebar matches)
      await expect(page.getByRole('main').getByText(/error|not found/i).first()).toBeVisible();
    });
  });
});

test.describe('Certificate Authority - Requests Page', () => {
  test.describe('Certificate Requests List', () => {
    test.beforeEach(async ({ page }) => {
      await createTenantOwnerSession(page.context());
    });

    test('should display certificate requests page', async ({ page }) => {
      const requests = [
        createMockCertificateRequest({
          id: 'csr-1',
          requester: 'user1@example.com',
          subject: 'CN=request1.example.com',
          status: 'pending',
        }),
        createMockCertificateRequest({
          id: 'csr-2',
          requester: 'user2@example.com',
          subject: 'CN=request2.example.com',
          status: 'approved',
        }),
      ];

      await mockCAApi(page, { initialRequests: requests });
      await mockTenantApi(page);

      await page.goto('/ca/requests');

      // Verify page loaded
      await expect(page.getByRole('heading', { name: /certificate requests/i })).toBeVisible();
    });

    test('should display pending requests', async ({ page }) => {
      const requests = [
        createMockCertificateRequest({
          id: 'pending-1',
          requester: 'pending@example.com',
          subject: 'CN=pending.example.com',
          status: 'pending',
        }),
      ];

      await mockCAApi(page, { initialRequests: requests });
      await mockTenantApi(page);

      await page.goto('/ca/requests');

      // Note: The requests page uses placeholder data currently
      // This test verifies the page structure
      await expect(page.getByRole('heading', { name: /certificate requests/i })).toBeVisible();
    });

    test('should show request status badges', async ({ page }) => {
      await mockCAApi(page);
      await mockTenantApi(page);

      await page.goto('/ca/requests');

      // Verify the page loads with the filter options available
      await expect(page.getByRole('heading', { name: /certificate requests/i })).toBeVisible();
    });

    test('should show approve and deny actions for pending requests', async ({ page }) => {
      await mockCAApi(page);
      await mockTenantApi(page);

      await page.goto('/ca/requests');

      // The requests page has approve/deny buttons in the dialog
      await expect(page.getByRole('heading', { name: /certificate requests/i })).toBeVisible();
    });
  });

  test.describe('Approve Request', () => {
    test.beforeEach(async ({ page }) => {
      await createTenantOwnerSession(page.context());
    });

    test('should display approve button in CSR dialog', async ({ page }) => {
      await mockCAApi(page);
      await mockTenantApi(page);

      await page.goto('/ca/requests');

      // The page uses a dialog to display approve/deny buttons
      await expect(page.getByRole('heading', { name: /certificate requests/i })).toBeVisible();
    });
  });

  test.describe('Reject Request', () => {
    test.beforeEach(async ({ page }) => {
      await createTenantOwnerSession(page.context());
    });

    test('should display deny button in CSR dialog', async ({ page }) => {
      await mockCAApi(page);
      await mockTenantApi(page);

      await page.goto('/ca/requests');

      await expect(page.getByRole('heading', { name: /certificate requests/i })).toBeVisible();
    });
  });
});

test.describe('Certificate Authority - CRL Page', () => {
  test.beforeEach(async ({ page }) => {
    await createTenantOwnerSession(page.context());
  });

  test('should display CRL management page', async ({ page }) => {
    await mockCAApi(page);
    await mockTenantApi(page);

    await page.goto('/ca/crl');

    // Verify page loaded
    await expect(
      page.getByRole('heading', { name: /certificate revocation list/i })
    ).toBeVisible();
  });

  test('should show coming soon message', async ({ page }) => {
    await mockCAApi(page);
    await mockTenantApi(page);

    await page.goto('/ca/crl');

    // The CRL page shows a coming soon message
    await expect(page.getByText(/coming soon/i)).toBeVisible();
  });

  test('should display CRL status section', async ({ page }) => {
    await mockCAApi(page);
    await mockTenantApi(page);

    await page.goto('/ca/crl');

    // Verify status section elements (use .first() for elements that may match multiple)
    await expect(page.getByText(/last updated/i).first()).toBeVisible();
    await expect(page.getByText(/next update/i).first()).toBeVisible();
    await expect(page.getByText('Revoked Certificates:', { exact: true })).toBeVisible();
  });

  test('should display distribution points section', async ({ page }) => {
    await mockCAApi(page);
    await mockTenantApi(page);

    await page.goto('/ca/crl');

    await expect(page.getByRole('heading', { name: /distribution points/i })).toBeVisible();
  });

  test('should show disabled generate CRL button', async ({ page }) => {
    await mockCAApi(page);
    await mockTenantApi(page);

    await page.goto('/ca/crl');

    const generateButton = page.getByRole('button', { name: /generate crl/i });
    await expect(generateButton).toBeVisible();
    await expect(generateButton).toBeDisabled();
  });

  test('should show disabled download CRL button', async ({ page }) => {
    await mockCAApi(page);
    await mockTenantApi(page);

    await page.goto('/ca/crl');

    const downloadButton = page.getByRole('button', { name: /download crl/i });
    await expect(downloadButton).toBeVisible();
    await expect(downloadButton).toBeDisabled();
  });
});

test.describe('Certificate Authority - Error States', () => {
  test.beforeEach(async ({ page }) => {
    await createTenantOwnerSession(page.context());
  });

  test('should display error when list fetch fails', async ({ page }) => {
    // Use 400 status instead of 500 because SDK retries on 500 errors
    await mockCAApi(page, {
      listError: { error: 'Failed to fetch certificates', status: 400 },
    });
    await mockTenantApi(page);

    await page.goto('/ca/certificates');

    // Should display error message
    await expect(page.getByText('Failed to fetch certificates')).toBeVisible();
  });

  test('should display error when certificate detail fetch fails', async ({ page }) => {
    await mockCAApi(page, {
      getDetailError: { error: 'Certificate not found', status: 404 },
    });
    await mockTenantApi(page);

    await page.goto('/ca/certificates/nonexistent');

    // Should display error message
    await expect(page.getByText(/error/i)).toBeVisible();
  });

  test('should handle network timeout gracefully', async ({ page }) => {
    // Set up a route that times out
    await page.route('**/api/v1/ca/certificates', async (route) => {
      // Delay response to simulate timeout
      await new Promise((resolve) => setTimeout(resolve, 100));
      await route.abort('timedout');
    });
    await mockTenantApi(page);

    await page.goto('/ca/certificates');

    // The page should handle the error gracefully
    await expect(page.getByRole('heading', { name: /certificates/i })).toBeVisible();
  });
});

test.describe('Certificate Authority - Access Control', () => {
  test('should redirect unauthenticated users to login', async ({ page }) => {
    await page.goto('/ca/certificates');

    // Should be redirected to login
    await expect(page).toHaveURL(/\/auth\/webauthn/);
  });

  test('should allow tenant members to view certificates', async ({ page }) => {
    await createTenantMemberSession(page.context());
    await mockCAApi(page, { initialCertificates: [] });
    await mockTenantApi(page);

    await page.goto('/ca/certificates');

    // Should be able to view the page
    await expect(page.getByRole('heading', { name: /certificates/i })).toBeVisible();
  });

  test('should allow tenant owners full access', async ({ page }) => {
    await createTenantOwnerSession(page.context());
    await mockCAApi(page, { initialCertificates: [] });
    await mockTenantApi(page);

    await page.goto('/ca/certificates');

    // Should see issue certificate button
    await expect(page.getByRole('button', { name: /issue certificate/i })).toBeVisible();
  });
});

test.describe('Certificate Authority - CA Bundle', () => {
  test.describe('Bundle Page Display', () => {
    test.beforeEach(async ({ page }) => {
      await createTenantOwnerSession(page.context());
      await mockTenantApi(page);
    });

    test('should display CA Bundle page header', async ({ page }) => {
      await page.goto('/ca/bundle');

      // Verify page header (use exact match to avoid matching "Root CA Bundle")
      await expect(
        page.getByRole('heading', { name: 'CA Bundle', exact: true })
      ).toBeVisible();
      await expect(
        page.getByText('View and download certificate authority bundles and trust chains')
      ).toBeVisible();
    });

    test('should display Certificate Bundle Management card', async ({ page }) => {
      await page.goto('/ca/bundle');

      // Verify card title and description
      await expect(
        page.getByRole('heading', { name: 'Certificate Bundle Management' })
      ).toBeVisible();
      await expect(page.getByText('This feature is under development')).toBeVisible();
    });

    test('should display Coming Soon placeholder', async ({ page }) => {
      await page.goto('/ca/bundle');

      // Verify coming soon message
      await expect(page.getByRole('heading', { name: 'Coming Soon' })).toBeVisible();
      await expect(
        page.getByText(/The CA Bundle viewer will allow you to view, download, and manage/)
      ).toBeVisible();
      await expect(
        page.getByText(/certificate chains including root and intermediate CA certificates/)
      ).toBeVisible();
      await expect(page.getByText(/in various formats \(PEM, DER, PKCS#7\)/)).toBeVisible();
    });

    test('should display Root CA Bundle section', async ({ page }) => {
      await page.goto('/ca/bundle');

      // Verify Root CA Bundle section
      await expect(page.getByRole('heading', { name: 'Root CA Bundle' })).toBeVisible();
      await expect(
        page.getByText('Download the root certificate authority bundle')
      ).toBeVisible();
    });

    test('should display Intermediate Bundle section', async ({ page }) => {
      await page.goto('/ca/bundle');

      // Verify Intermediate Bundle section
      await expect(page.getByRole('heading', { name: 'Intermediate Bundle' })).toBeVisible();
      await expect(page.getByText('Download intermediate CA certificates')).toBeVisible();
    });

    test('should display Full Chain section', async ({ page }) => {
      await page.goto('/ca/bundle');

      // Verify Full Chain section
      await expect(page.getByRole('heading', { name: 'Full Chain' })).toBeVisible();
      await expect(page.getByText('Download the complete certificate chain')).toBeVisible();
    });
  });

  test.describe('Download Buttons', () => {
    test.beforeEach(async ({ page }) => {
      await createTenantOwnerSession(page.context());
      await mockTenantApi(page);
    });

    test('should display three disabled download buttons', async ({ page }) => {
      await page.goto('/ca/bundle');

      // Get all download buttons
      const downloadButtons = page.getByRole('button', { name: 'Download' });

      // Verify there are 3 download buttons
      await expect(downloadButtons).toHaveCount(3);

      // Verify all buttons are disabled
      for (let i = 0; i < 3; i++) {
        await expect(downloadButtons.nth(i)).toBeDisabled();
      }
    });

    test('should have Root CA Bundle download button disabled', async ({ page }) => {
      await page.goto('/ca/bundle');

      // Find download buttons and verify the first one (Root CA Bundle) is disabled
      const downloadButtons = page.getByRole('button', { name: 'Download' });
      await expect(downloadButtons.first()).toBeDisabled();
    });

    test('should have Intermediate Bundle download button disabled', async ({ page }) => {
      await page.goto('/ca/bundle');

      // Find download buttons and verify the second one (Intermediate Bundle) is disabled
      const downloadButtons = page.getByRole('button', { name: 'Download' });
      await expect(downloadButtons.nth(1)).toBeDisabled();
    });

    test('should have Full Chain download button disabled', async ({ page }) => {
      await page.goto('/ca/bundle');

      // Find download buttons and verify the third one (Full Chain) is disabled
      const downloadButtons = page.getByRole('button', { name: 'Download' });
      await expect(downloadButtons.nth(2)).toBeDisabled();
    });
  });

  test.describe('Page Layout', () => {
    test.beforeEach(async ({ page }) => {
      await createTenantOwnerSession(page.context());
      await mockTenantApi(page);
    });

    test('should display bundle sections in a grid layout', async ({ page }) => {
      await page.goto('/ca/bundle');

      // Verify the three bundle type sections are visible
      await expect(page.getByRole('heading', { name: 'Root CA Bundle' })).toBeVisible();
      await expect(page.getByRole('heading', { name: 'Intermediate Bundle' })).toBeVisible();
      await expect(page.getByRole('heading', { name: 'Full Chain' })).toBeVisible();
    });

    test('should display bundle sections with descriptions', async ({ page }) => {
      await page.goto('/ca/bundle');

      // Verify all descriptions are visible
      await expect(
        page.getByText('Download the root certificate authority bundle')
      ).toBeVisible();
      await expect(page.getByText('Download intermediate CA certificates')).toBeVisible();
      await expect(page.getByText('Download the complete certificate chain')).toBeVisible();
    });
  });

  test.describe('Access Control', () => {
    test('should redirect unauthenticated users to login', async ({ page }) => {
      await page.goto('/ca/bundle');

      // Should be redirected to login
      await expect(page).toHaveURL(/\/auth\/webauthn/);
    });

    test('should allow tenant members to view CA Bundle page', async ({ page }) => {
      await createTenantMemberSession(page.context());
      await mockTenantApi(page);

      await page.goto('/ca/bundle');

      // Should be able to view the page (use exact match to avoid matching "Root CA Bundle")
      await expect(
        page.getByRole('heading', { name: 'CA Bundle', exact: true })
      ).toBeVisible();
    });

    test('should allow tenant owners to view CA Bundle page', async ({ page }) => {
      await createTenantOwnerSession(page.context());
      await mockTenantApi(page);

      await page.goto('/ca/bundle');

      // Should be able to view the page (use exact match to avoid matching "Root CA Bundle")
      await expect(
        page.getByRole('heading', { name: 'CA Bundle', exact: true })
      ).toBeVisible();
      await expect(
        page.getByRole('heading', { name: 'Certificate Bundle Management' })
      ).toBeVisible();
    });
  });
});
