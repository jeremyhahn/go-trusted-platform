import { test, expect, Page } from '@playwright/test';
import { createTenantOwnerSession } from './fixtures/auth-setup';
import { mockTenantApi, errorEnvelope } from './fixtures/api-mock';
import { mockDeviceApi, createMockDeviceDetail } from './fixtures/device-api-mock';
import type { Device, DeviceDetail } from './fixtures/device-api-mock';

/**
 * "Record certificate" on the device detail page (#491).
 *
 * POST /api/v1/devices/{id}/attest-cert/record (docs/device/api.md §4.5)
 * records the device's attestation certificate without re-enrolling. The
 * server fails closed with no override; the console offers only the opt-in
 * CA re-issuance, behind a confirm step, and shows a refusal verbatim.
 *
 * The API is mocked at the route layer like the rest of the suite, with the
 * shapes the server emits (RecordAttestCertResponse, the platform error
 * envelope).
 */

const PEM = '-----BEGIN CERTIFICATE-----\nMIIBrecorded\n-----END CERTIFICATE-----\n';

const REFUSAL =
  'device: attestation certificate refused for device 1; nothing recorded: ' +
  'device: no certificate on the record; ca[node-03]: lacks tcg-cap-verifiedTPMRestricted';

interface RecordMock {
  /** The `reissue` flag of every POST, in order */
  requests: boolean[];
}

/**
 * Mocks the record route and the device detail around it. `refuse` answers
 * 400 with REFUSAL; otherwise the call records PEM and the next device read
 * carries it, as the server's record would.
 */
async function openDetailWithRecord(page: Page, options: { refuse?: boolean } = {}): Promise<RecordMock> {
  const detail = {
    ...createMockDeviceDetail({ id: 1, model: 'Device-1' }),
    attest_pub: 'mock-attest-pub-key',
    ek_cert: 'mock-ek-certificate',
  };
  const requests: boolean[] = [];
  let recorded = false;

  await mockDeviceApi(page, { initialDevices: [detail as unknown as Device], deviceDetail: detail as unknown as DeviceDetail });
  await mockTenantApi(page);

  await page.route('**/api/v1/attestation/reports/*', async (route) => {
    await route.fulfill({ status: 404, contentType: 'application/json', body: errorEnvelope({ status: 404, error: 'attestation: no report has been collected for device 1' }) });
  });

  await page.route('**/api/v1/devices/1', async (route) => {
    if (route.request().method() !== 'GET' || !recorded) {
      await route.fallback();
      return;
    }
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ ...detail, attest_cert: PEM }) });
  });

  await page.route('**/api/v1/devices/*/attest-cert/record', async (route) => {
    const body = route.request().postDataJSON() as { reissue: boolean };
    requests.push(body.reissue);
    if (options.refuse) {
      await route.fulfill({ status: 400, contentType: 'application/json', body: JSON.stringify({ code: 400, error: REFUSAL, success: false, payload: null }) });
      return;
    }
    recorded = true;
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        code: 200,
        success: true,
        payload: {
          device_id: '1',
          changed: true,
          source: body.reissue ? 'reissued' : 'ca',
          source_detail: 'iak-Device-1-SN-00000001',
          reissued: body.reissue,
          subject: 'CN=iak-Device-1-SN-00000001',
          certificate_serial: '1f2e3d',
          not_after: '9999-12-31T23:59:59Z',
          attest_cert: PEM,
        },
      }),
    });
  });

  await page.goto('/devices/__placeholder__/');
  // pushState is only router-integrated once the app has hydrated.
  await page.getByText('Loading device details').waitFor();
  await page.waitForLoadState('networkidle');
  await page.evaluate(() => window.history.pushState(null, '', '/devices/1/'));
  await expect(page.getByTestId('attest-cert-card')).toBeVisible();
  return { requests };
}

test.describe('Record attestation certificate (#491)', () => {
  test.beforeEach(async ({ page }) => {
    await createTenantOwnerSession(page.context());
  });

  test('a device with no certificate says so and records one without re-issuing by default', async ({ page }) => {
    const { requests } = await openDetailWithRecord(page);
    await expect(page.getByTestId('attest-cert-absent')).toBeVisible();

    await page.getByRole('button', { name: /record certificate/i }).click();
    await expect(page.getByRole('checkbox', { name: /re-issue/i })).not.toBeChecked();
    await page.getByRole('button', { name: /^record$/i }).click();

    await expect(page.getByText('Certificate recorded')).toBeVisible();
    expect(requests).toEqual([false]);
    await expect(page.getByTestId('attest-cert-absent')).toBeHidden();
    await expect(page.getByTestId('attest-cert-card')).toContainText('MIIBrecorded');
  });

  test('re-issuance is opt-in behind a confirm step that warns the CA will issue', async ({ page }) => {
    const { requests } = await openDetailWithRecord(page);

    await page.getByRole('button', { name: /record certificate/i }).click();
    await expect(page.getByTestId('attest-cert-reissue-warning')).toBeHidden();
    await page.getByRole('checkbox', { name: /re-issue/i }).check();
    await expect(page.getByTestId('attest-cert-reissue-warning')).toBeVisible();
    await page.getByRole('button', { name: /record and re-issue/i }).click();

    await expect(page.getByText('Certificate recorded')).toBeVisible();
    expect(requests).toEqual([true]);
  });

  test('a refusal (400) is shown verbatim and nothing is recorded', async ({ page }) => {
    const { requests } = await openDetailWithRecord(page, { refuse: true });

    await page.getByRole('button', { name: /record certificate/i }).click();
    await page.getByRole('button', { name: /^record$/i }).click();

    await expect(page.getByTestId('attest-cert-refusal')).toHaveText(REFUSAL);
    expect(requests).toEqual([false]);
    await page.getByRole('button', { name: /cancel/i }).click();
    await expect(page.getByTestId('attest-cert-absent')).toBeVisible();
  });
});
