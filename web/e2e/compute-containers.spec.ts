import { test, expect } from '@playwright/test';
import { createTenantOwnerSession } from './fixtures/auth-setup';
import { mockContainerOpsApi, mockTenantApi } from './fixtures/api-mock';

/**
 * Container detail, exec, metrics and attestation pages (#1721), and the
 * VM attestation verify action on the VM detail page. Every API response
 * is mocked through fixtures/api-mock.ts.
 */
test.describe('Compute containers: detail, exec, metrics and attestation (#1721)', () => {
  test.beforeEach(async ({ page }) => {
    await createTenantOwnerSession(page.context());
    await mockTenantApi(page);
  });

  test('GetContainer shows the container detail page', async ({ page }) => {
    const calls = await mockContainerOpsApi(page, { containerId: 'ctr-1', containerName: 'web-frontend' });

    await page.goto('/compute/containers/ctr-1');

    await expect(page.getByRole('heading', { name: 'web-frontend' })).toBeVisible();
    await expect(page.getByText('nginx:1.27')).toBeVisible();
    await expect(page.getByText('host-a')).toBeVisible();
    expect(calls.getContainer).toBeGreaterThan(0);
  });

  test('GetContainerMetrics shows the metrics panel', async ({ page }) => {
    const calls = await mockContainerOpsApi(page, { containerId: 'ctr-1' });

    await page.goto('/compute/containers/ctr-1');

    const panel = page.getByTestId('container-metrics');
    await expect(panel.getByText('12.5%')).toBeVisible();
    await expect(panel.getByText('256 / 512 MB')).toBeVisible();
    await expect(panel.getByText('3600 s')).toBeVisible();
    expect(calls.getMetrics).toBeGreaterThan(0);
  });

  test('ExecContainer runs a command after confirmation', async ({ page }) => {
    const calls = await mockContainerOpsApi(page, { containerId: 'ctr-1' });

    await page.goto('/compute/containers/ctr-1');
    await page.getByLabel('Command').fill(`sh -c 'echo hello' ""`);
    await page.getByRole('button', { name: 'Run' }).click();

    const dialog = page.getByRole('dialog');
    await expect(dialog.getByText('Run command in container?')).toBeVisible();
    expect(calls.exec).toHaveLength(0);

    await dialog.getByRole('button', { name: 'Confirm' }).click();

    const result = page.getByTestId('exec-result');
    await expect(result.getByText('hello from container')).toBeVisible();
    await expect(result.getByText('Exit code: 0')).toBeVisible();
    expect(calls.exec).toEqual([
      expect.objectContaining({ command: ['sh', '-c', 'echo hello', ''] }),
    ]);
  });

  test('ExecContainer is not sent when the confirm dialog is cancelled', async ({ page }) => {
    const calls = await mockContainerOpsApi(page, { containerId: 'ctr-1' });

    await page.goto('/compute/containers/ctr-1');
    await page.getByLabel('Command').fill('rm -rf /tmp/x');
    await page.getByRole('button', { name: 'Run' }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Cancel' }).click();

    await expect(page.getByRole('dialog')).toBeHidden();
    await expect(page.getByTestId('exec-result')).toHaveCount(0);
    expect(calls.exec).toHaveLength(0);
  });

  test('AttestContainer requests an attestation after confirmation', async ({ page }) => {
    const calls = await mockContainerOpsApi(page, { containerId: 'ctr-1' });

    await page.goto('/compute/containers/ctr-1');
    await page.getByRole('button', { name: 'Attest' }).click();

    const dialog = page.getByRole('dialog');
    await expect(dialog.getByText('Attest container?')).toBeVisible();
    await dialog.getByRole('button', { name: 'Confirm' }).click();

    const result = page.getByTestId('attest-result');
    await expect(result.getByText('Verified', { exact: true })).toBeVisible();
    await expect(result.getByText('aW1hZ2UtZGlnZXN0')).toBeVisible();
    expect(calls.attest).toHaveLength(1);
    expect((calls.attest[0] as { nonce?: string }).nonce).toMatch(/^[A-Za-z0-9+/]+=*$/);
  });

  test('VerifyVMAttestation verifies a VM attestation from the VM detail page', async ({ page }) => {
    const calls = await mockContainerOpsApi(page, { vmId: 'vm-1', vmName: 'build-vm' });

    await page.goto('/compute/vms/vm-1');
    await expect(page.getByRole('heading', { name: 'build-vm' })).toBeVisible();
    await page.getByRole('button', { name: 'Verify Attestation' }).click();

    const dialog = page.getByRole('dialog');
    await expect(dialog.getByText('Verify VM attestation?')).toBeVisible();
    await dialog.getByRole('button', { name: 'Confirm' }).click();

    await expect(page.getByTestId('vm-verify-result').getByText('Attestation verified')).toBeVisible();
    expect(calls.vmAttest).toHaveLength(1);
    const nonce = (calls.vmAttest[0] as { nonce: string }).nonce;
    expect(calls.vmVerify).toEqual([
      expect.objectContaining({
        nonce,
        quote: 'cXVvdGU=',
        signature: 'c2ln',
        signatureAlgorithm: 'SHA256-RSAPSS',
      }),
    ]);
  });

  test('the containers list links each container to its detail page', async ({ page }) => {
    await mockContainerOpsApi(page, { containerId: 'ctr-1', containerName: 'web-frontend' });
    await page.route('**/api/v1/compute/containers*', async (route, request) => {
      if (request.method() !== 'GET' || /\/containers\/[^/?]/.test(request.url())) {
        await route.fallback();
        return;
      }
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          containers: [
            {
              id: 'ctr-1',
              name: 'web-frontend',
              image: 'nginx:1.27',
              config: { name: 'web-frontend', image: 'nginx:1.27' },
              state: 'CONTAINER_STATE_RUNNING',
              createdAt: new Date().toISOString(),
            },
          ],
          pagination: { page: 1, pageSize: 100, totalPages: 1, totalItems: 1 },
        }),
      });
    });

    await page.goto('/compute/containers');
    await page.getByRole('link', { name: 'web-frontend' }).click();

    await expect(page).toHaveURL(/\/compute\/containers\/ctr-1\/?$/);
    await expect(page.getByRole('heading', { name: 'web-frontend' })).toBeVisible();
  });
});
