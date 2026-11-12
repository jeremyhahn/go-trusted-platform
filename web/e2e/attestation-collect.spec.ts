import { test, expect, Page } from '@playwright/test';
import { createTenantOwnerSession } from './fixtures/auth-setup';
import { mockTenantApi, errorEnvelope } from './fixtures/api-mock';

// #1732 (epic #1665, slice 1): attestation collect and manifest delete from
// the dashboard. Manifest verification is not offered until the verifier
// fails closed (#1732 review).

interface Call {
  method: string;
  path: string;
  body: unknown;
}

function envelope(payload: unknown, code = 200): string {
  return JSON.stringify({ code, success: true, payload });
}

/** Mocks the attestation routes this page drives and records each call. */
async function mockCollectApi(page: Page) {
  const calls: Call[] = [];
  await page.route('**/api/v1/attestation/**', async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname.replace(/^.*\/api\/v1\/attestation/, '');
    const method = request.method();
    let body: unknown = undefined;
    try {
      body = request.postDataJSON();
    } catch {
      body = request.postData();
    }
    calls.push({ method, path, body });

    if (method === 'POST' && path === '/host') {
      await route.fulfill({ status: 200, contentType: 'application/json', body: envelope({ status: { success: true }, attestation: { hostId: 'host-under-test' } }) });
      return;
    }
    if (method === 'POST' && path.startsWith('/vm/')) {
      await route.fulfill({ status: 200, contentType: 'application/json', body: envelope({ vm_id: decodeURIComponent(path.slice(4)), host_id: 'host-under-test', verified: true, quote_data: 'cQ==', signature: 'cw==', signature_algorithm: 'RSASSA' }) });
      return;
    }
    if (method === 'POST' && path.startsWith('/container/')) {
      await route.fulfill({ status: 200, contentType: 'application/json', body: envelope({ container_id: decodeURIComponent(path.slice(11)), verified: true, digest: 'sha256:abc', pcr_value: 'cA==' }) });
      return;
    }
    if (method === 'POST' && path === '/manifests/verify') {
      // The page must not offer manifest verification until the verifier
      // fails closed (#1732 review); a call here is recorded and refused.
      await route.fulfill({ status: 500, contentType: 'application/json', body: errorEnvelope({ status: 500, error: 'manifest verification is not offered' }) });
      return;
    }
    if (method === 'DELETE' && path.startsWith('/manifests/')) {
      await route.fulfill({ status: 200, contentType: 'application/json', body: envelope({ status: { success: true, message: 'deleted' } }) });
      return;
    }
    await route.fulfill({ status: 404, contentType: 'application/json', body: errorEnvelope({ status: 404, error: 'not mocked' }) });
  });
  return calls;
}

async function openCollectPage(page: Page) {
  await createTenantOwnerSession(page.context());
  await mockTenantApi(page);
  const calls = await mockCollectApi(page);
  await page.goto('/attestation/collect');
  await expect(page.getByRole('heading', { name: 'Attestation Collect' })).toBeVisible();
  return calls;
}

test.describe('Attestation collect and manifests (#1732)', () => {
  test('the page offers no manifest verification (#1732 review)', async ({ page }) => {
    const calls = await openCollectPage(page);
    await expect(page.getByLabel('Manifest JSON')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Verify manifest' })).toHaveCount(0);

    await page.getByRole('button', { name: 'Collect host attestation' }).click();
    await expect(page.getByTestId('collect-result')).toContainText('host-under-test');
    await page.getByLabel('Manifest ID').fill('m-1');
    await page.getByRole('button', { name: 'Delete manifest' }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Confirm delete' }).click();
    await expect(page.getByTestId('collect-result')).toContainText('Manifest deletion');

    expect(calls.filter((c) => c.path === '/manifests/verify')).toHaveLength(0);
  });

  test('DeleteManifest: DELETE /manifests/{id} after confirm', async ({ page }) => {
    const calls = await openCollectPage(page);
    await page.getByLabel('Manifest ID').fill('m-42');
    await page.getByRole('button', { name: 'Delete manifest' }).click();

    // Cancel first: nothing is deleted.
    const dialog = page.getByRole('dialog');
    await expect(dialog).toContainText('Delete manifest?');
    await dialog.getByRole('button', { name: 'Cancel' }).click();
    await expect(dialog).toBeHidden();
    expect(calls.filter((c) => c.method === 'DELETE')).toHaveLength(0);

    await page.getByRole('button', { name: 'Delete manifest' }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Confirm delete' }).click();
    await expect(page.getByTestId('collect-result')).toContainText('Manifest deletion');
    const deletes = calls.filter((c) => c.method === 'DELETE');
    expect(deletes.map((c) => c.path)).toEqual(['/manifests/m-42']);
  });

  test('CollectHostAttestation: POST /host shows the result', async ({ page }) => {
    const calls = await openCollectPage(page);
    await page.getByRole('button', { name: 'Collect host attestation' }).click();

    await expect(page.getByTestId('collect-result')).toContainText('host-under-test');
    const call = calls.find((c) => c.path === '/host');
    expect(call?.method).toBe('POST');
    const nonce = (call?.body as { nonce?: string } | undefined)?.nonce ?? '';
    expect(nonce.length).toBeGreaterThan(0);
  });

  test('CollectVMAttestation: POST /vm/{id} shows the result', async ({ page }) => {
    const calls = await openCollectPage(page);
    await page.getByLabel('VM ID').fill('vm-7');
    await page.getByRole('button', { name: 'Collect VM attestation' }).click();

    const result = page.getByTestId('collect-result');
    await expect(result).toContainText('VM attestation');
    await expect(result).toContainText('vm-7');
    expect(calls.find((c) => c.path === '/vm/vm-7')?.method).toBe('POST');
  });

  test('CollectContainerAttestation: POST /container/{id} shows the result', async ({ page }) => {
    const calls = await openCollectPage(page);
    await page.getByLabel('Container ID').fill('ctr-9');
    await page.getByRole('button', { name: 'Collect container attestation' }).click();

    const result = page.getByTestId('collect-result');
    await expect(result).toContainText('Container attestation');
    await expect(result).toContainText('ctr-9');
    expect(calls.find((c) => c.path === '/container/ctr-9')?.method).toBe('POST');
  });

  test('the sidebar lists the collect page', async ({ page }) => {
    await openCollectPage(page);
    await expect(page.locator('a[href="/attestation/collect"]').first()).toBeAttached();
  });
});
