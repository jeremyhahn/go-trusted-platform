/**
 * Real-server spec for the attestation operations of row #2038 (epic #1665).
 *
 * Every flow seeds state through the SDK client (`sdk`) and asserts on what
 * the harness server returns: no route mocks. The page under test is driven
 * by the logged-in `adminPage`.
 */
import type { PlatformClient } from 'trusted-platform-sdk';
import { test, expect } from './fixtures';

async function buildManifest(sdk: PlatformClient) {
  const built = await sdk.attestation.buildManifest({ config: {}, includeVms: false, sign: false });
  expect(built.success, built.error?.message).toBe(true);
  const manifest = built.data?.manifest;
  expect(manifest).toBeTruthy();
  return manifest!;
}

test.describe('attestation: manifests', () => {
  test('verify manifest shows the verdict the server returns', async ({ adminPage, sdk }) => {
    const manifest = await buildManifest(sdk);
    const server = await sdk.attestation.verifyManifest({ manifest });

    await adminPage.goto('/attestation/verify');
    await adminPage.getByLabel('Manifest JSON').fill(JSON.stringify(manifest));
    await adminPage.getByRole('button', { name: 'Verify manifest' }).click();

    const result = adminPage.getByTestId('verify-manifest-result');
    await expect(result).toBeVisible();
    if (server.success) {
      await expect(result).toContainText(String(server.data?.result?.status ?? ''));
    } else {
      await expect(result).toContainText(server.error?.message ?? 'failed');
    }
  });

  test('delete manifest removes it on the server', async ({ adminPage, sdk }) => {
    const manifest = await buildManifest(sdk);
    const id = manifest.id;
    expect(id).toBeTruthy();

    await adminPage.goto('/attestation/collect');
    await adminPage.getByLabel('Manifest ID').fill(id!);
    await adminPage.getByRole('button', { name: 'Delete manifest' }).click();
    await adminPage.getByRole('button', { name: 'Confirm delete' }).click();
    await expect(adminPage.getByTestId('collect-result')).toBeVisible();

    const after = await sdk.attestation.getManifest(id!);
    expect(after.success).toBe(false);
  });
});

test.describe('attestation: quotes', () => {
  test('get and verify a quote round trip through the page', async ({ adminPage, sdk }) => {
    const probe = await sdk.attestation.getQuote({ config: {}, nonce: 'cHJvYmU=' });

    await adminPage.goto('/attestation/quotes');
    await adminPage.getByRole('button', { name: 'Get quote' }).click();
    const quote = adminPage.getByTestId('quote-result');
    await expect(quote).toBeVisible();

    if (!probe.success) {
      // The server cannot quote (no TPM session): the page shows its error.
      await expect(quote).toContainText(probe.error?.message ?? 'failed');
      return;
    }

    // A quote checked against a key that did not sign it never verifies.
    await adminPage.getByLabel('AK public key (PEM)').fill('not-a-key');
    await adminPage.getByRole('button', { name: 'Verify quote' }).click();
    const verdict = adminPage.getByTestId('quote-verify-result');
    await expect(verdict).toBeVisible();
    await expect(verdict).not.toContainText('Verified');
  });
});

test.describe('attestation: collection', () => {
  test('collect host attestation shows the server result', async ({ adminPage, sdk }) => {
    const server = await sdk.attestation.collectHostAttestation({ config: {}, nonce: 'cHJvYmU=' });

    await adminPage.goto('/attestation/collect');
    await adminPage.getByRole('button', { name: 'Collect host attestation' }).click();
    if (server.success) {
      await expect(adminPage.getByTestId('collect-result')).toBeVisible();
    } else {
      await expect(adminPage.getByTestId('collect-error')).toBeVisible();
    }
  });

  // VM and container collection are gated off: the attestation service has no
  // daemon-managed TPM session for workloads, so the server refuses both.
  test('VM and container collection are gated off with the reason', async ({ adminPage, sdk }) => {
    const vm = await sdk.attestation.collectVMAttestation({ vmId: 'e2e-vm', config: {}, nonce: 'cHJvYmU=' });
    const ctr = await sdk.attestation.collectContainerAttestation({ containerId: 'e2e-ctr' });
    expect(vm.success).toBe(false);
    expect(ctr.success).toBe(false);

    await adminPage.goto('/attestation/collect');
    await expect(adminPage.getByTestId('workload-collect-unavailable')).toBeVisible();
    await adminPage.getByLabel('VM ID').fill('e2e-vm');
    await expect(adminPage.getByRole('button', { name: 'Collect VM attestation' })).toBeDisabled();
    await adminPage.getByLabel('Container ID').fill('e2e-ctr');
    await expect(adminPage.getByRole('button', { name: 'Collect container attestation' })).toBeDisabled();
  });
});

test.describe('attestation: device verdicts', () => {
  test('verdicts page polls the feed the server returns', async ({ adminPage, sdk }) => {
    const server = await sdk.attestation.pollDeviceVerdicts({});

    await adminPage.goto('/attestation/verdicts');
    const panel = adminPage.getByTestId('device-verdicts');
    await expect(panel).toBeVisible();
    if (!server.success) {
      await expect(panel).toContainText(server.error?.message ?? 'failed');
      return;
    }
    const verdicts = server.data?.verdicts ?? [];
    if (verdicts.length === 0) {
      await expect(panel).toContainText('No verdicts');
    } else {
      await expect(panel).toContainText(verdicts[0].serial || verdicts[0].deviceId);
    }
    await adminPage.getByRole('button', { name: 'Poll again' }).click();
    await expect(panel).toBeVisible();
  });
});

test.describe('attestation: caller policy', () => {
  test('caller policy page lists what the server describes', async ({ adminPage, sdk }) => {
    const server = await sdk.attestation.describeCallers();

    await adminPage.goto('/attestation/callers');
    const panel = adminPage.getByTestId('caller-policy');
    await expect(panel).toBeVisible();
    if (server.success) {
      await expect(panel).not.toContainText('failed');
    } else {
      await expect(panel).toContainText(server.error?.message ?? 'failed');
    }
  });
});
