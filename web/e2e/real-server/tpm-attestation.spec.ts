import { test, expect } from './fixtures';

/**
 * TPM and attestation pages against the real server.
 *
 * Ported from web/e2e/tpm-attestation.spec.ts (#2037). TPM facts are read from
 * sdk.tpm.getInfo() and compared with the page; manifests are seeded through
 * sdk.attestation.buildManifest. Injected errors (TPM unavailable, NVRAM,
 * seal/unseal, attestation fetch, manifest build), empty-state, forged
 * Draft/Archived/Expired statuses and member-session cases had no server
 * behaviour behind them and are listed as gaps in the PR body.
 */

const unique = (prefix: string): string =>
  `${prefix}-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function must<T>(res: { success: boolean; data?: T; error?: any }, what: string): T {
  if (!res.success || res.data === undefined) {
    throw new Error(`${what} failed: ${JSON.stringify(res.error)}`);
  }
  return res.data;
}

test.describe('TPM Management (real server)', () => {
  test.describe('TPM Status Page', () => {
    test('displays TPM status', async ({ adminPage }) => {
      await adminPage.goto('/tpm/status');

      await expect(adminPage.getByRole('heading', { name: /tpm status/i })).toBeVisible();
      await expect(adminPage.getByText('Available')).toBeVisible();
    });

    test('shows the manufacturer the server reports', async ({ adminPage, sdk }) => {
      const info = must(await sdk.tpm.getInfo(), 'tpm.getInfo');
      test.skip(!info.manufacturer, 'server could not identify the TPM manufacturer');

      await adminPage.goto('/tpm/status');
      await expect(adminPage.getByText(info.manufacturer.name).first()).toBeVisible();
    });

    test('shows the TPM version', async ({ adminPage }) => {
      await adminPage.goto('/tpm/status');
      await expect(adminPage.getByText(/TPM 2.0/i).first()).toBeVisible();
    });

    test('shows capabilities and hierarchies', async ({ adminPage }) => {
      await adminPage.goto('/tpm/status');

      await expect(adminPage.getByText('Capabilities')).toBeVisible();
      const main = adminPage.locator('main');
      await expect(main.getByText('Platform', { exact: true })).toBeVisible();
      await expect(main.getByText('Storage', { exact: true })).toBeVisible();
      await expect(main.getByText('Endorsement', { exact: true })).toBeVisible();
    });

    test('refresh keeps the server values', async ({ adminPage, sdk }) => {
      const info = must(await sdk.tpm.getInfo(), 'tpm.getInfo');
      await adminPage.goto('/tpm/status');
      await expect(adminPage.getByRole('heading', { name: /tpm status/i })).toBeVisible();

      await adminPage.getByRole('button', { name: /refresh/i }).click();

      await expect(adminPage.getByRole('heading', { name: /tpm status/i })).toBeVisible();
      if (info.manufacturer) {
        await expect(adminPage.getByText(info.manufacturer.name).first()).toBeVisible();
      }
    });
  });

  test.describe('TPM Keys Page', () => {
    test('lists keys with the table columns', async ({ adminPage }) => {
      await adminPage.goto('/tpm/keys');

      await expect(adminPage.getByRole('heading', { name: /tpm keys/i })).toBeVisible();
      await expect(adminPage.getByText('Total Keys')).toBeVisible();
      await expect(adminPage.getByText('Key hierarchy root', { exact: true })).toBeVisible();
    });

    test('shows the key hierarchy documentation', async ({ adminPage }) => {
      await adminPage.goto('/tpm/keys');

      await expect(adminPage.getByRole('heading', { name: 'Key Hierarchy' })).toBeVisible();
      await expect(adminPage.getByText(/storage root key.*serves as the parent/i)).toBeVisible();
    });
  });

  test.describe('PCR Values Page', () => {
    test('displays the PCR table and statistics', async ({ adminPage }) => {
      await adminPage.goto('/tpm/pcrs');

      await expect(adminPage.locator('h1').filter({ hasText: /pcr/i })).toBeVisible();
      await expect(adminPage.getByRole('columnheader', { name: /pcr/i })).toBeVisible();
      await expect(adminPage.getByRole('columnheader', { name: /description/i })).toBeVisible();
      await expect(adminPage.getByRole('columnheader', { name: /value/i })).toBeVisible();
      await expect(adminPage.getByText('Total PCRs')).toBeVisible();
      await expect(adminPage.getByText('Measured PCRs')).toBeVisible();
      await expect(adminPage.getByText('Unused PCRs')).toBeVisible();
    });

    test('displays the PCR 0 description', async ({ adminPage }) => {
      await adminPage.goto('/tpm/pcrs');
      await expect(adminPage.getByText('BIOS/UEFI code').first()).toBeVisible();
    });

    test('defaults to the SHA-256 bank', async ({ adminPage }) => {
      await adminPage.goto('/tpm/pcrs');
      await expect(adminPage.getByText(/sha-256/i).first()).toBeVisible();
    });

    test('shows the PCR documentation', async ({ adminPage }) => {
      await adminPage.goto('/tpm/pcrs');

      await expect(adminPage.getByText('PCR Reference')).toBeVisible();
      await expect(adminPage.getByText('Boot PCRs (0-7)')).toBeVisible();
      await expect(adminPage.getByText('OS PCRs (8-15)')).toBeVisible();
    });
  });

  test.describe('NVRAM Page', () => {
    test('displays NVRAM capacity and documentation', async ({ adminPage }) => {
      await adminPage.goto('/tpm/nvram');

      await expect(adminPage.getByRole('heading', { name: /nvram management/i })).toBeVisible();
      await expect(adminPage.getByText('Max NVRAM Size')).toBeVisible();
      await expect(adminPage.getByText('TPM Version')).toBeVisible();
      await expect(adminPage.getByText('NVRAM Reference')).toBeVisible();
    });
  });

  test.describe('Seal/Unseal Page', () => {
    test('displays the seal and unseal tabs and PCR choices', async ({ adminPage }) => {
      await adminPage.goto('/tpm/seal');

      await expect(adminPage.locator('h1').filter({ hasText: /seal\/unseal/i })).toBeVisible();
      await expect(adminPage.getByRole('tab', { name: /seal data/i }).first()).toBeVisible();
      await expect(adminPage.getByRole('tab', { name: /unseal data/i }).first()).toBeVisible();
      await expect(adminPage.getByText('PCR 0').first()).toBeVisible();
      await expect(adminPage.getByText('PCR 7', { exact: true })).toBeVisible();
    });

    test('requires a common name for sealing', async ({ adminPage }) => {
      await adminPage.goto('/tpm/seal');
      await adminPage.fill('textarea[id="seal-data"]', 'secret-data');

      await expect(adminPage.getByRole('button', { name: /seal data/i }).first()).toBeDisabled();
    });

    test('seals data and unseals it again on the server', async ({ adminPage }) => {
      const cn = unique('e2e-seal');

      await adminPage.goto('/tpm/seal');
      await adminPage.fill('input[id="seal-cn"]', cn);
      await adminPage.fill('textarea[id="seal-data"]', 'my-secret-data');
      await adminPage.getByRole('button', { name: /seal data/i }).first().click();

      await expect(adminPage.getByText(/sealed successfully/i).first()).toBeVisible();

      await adminPage.getByRole('tab', { name: /unseal data/i }).first().click();
      await adminPage.fill('input[id="unseal-cn"]', cn);
      await adminPage.getByRole('button', { name: /unseal data/i }).click();

      await expect(adminPage.getByText(/unsealed successfully/i).first()).toBeVisible();
      await expect(adminPage.getByText('my-secret-data').first()).toBeVisible();
    });

    test('unsealing an unknown name reports the server error', async ({ adminPage }) => {
      await adminPage.goto('/tpm/seal');
      await adminPage.getByRole('tab', { name: /unseal data/i }).first().click();
      await adminPage.fill('input[id="unseal-cn"]', unique('never-sealed'));
      await adminPage.getByRole('button', { name: /unseal data/i }).click();

      await expect(adminPage.getByText(/error|failed|not found/i).first()).toBeVisible();
    });

    test('shows the seal/unseal documentation', async ({ adminPage }) => {
      await adminPage.goto('/tpm/seal');

      await expect(adminPage.getByText('Seal/Unseal Reference')).toBeVisible();
      await expect(adminPage.getByText('Common Use Cases')).toBeVisible();
      await expect(adminPage.getByText('Best Practices')).toBeVisible();
    });
  });
});

test.describe('Attestation Management (real server)', () => {
  async function seedManifest(
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    sdk: any,
    hostId: string,
    sign = true,
  ): Promise<{ id: string; hostId: string }> {
    const built = must(
      await sdk.attestation.buildManifest({ config: { hostId }, sign }),
      'attestation.buildManifest',
    );
    const manifest = built.manifest ?? built;
    return { id: manifest.id, hostId: manifest.hostId ?? hostId };
  }

  test('lists a manifest built on the server', async ({ adminPage, sdk }) => {
    const m = await seedManifest(sdk, unique('list-host'));

    await adminPage.goto('/attestation');

    await expect(adminPage.getByText(m.hostId).first()).toBeVisible();
  });

  test('labels manifests by signature, never as a verdict', async ({ adminPage, sdk }) => {
    const signed = await seedManifest(sdk, unique('alpha-host'), true);
    const unsigned = await seedManifest(sdk, unique('bravo-host'), false);

    await adminPage.goto('/attestation');
    const rowFor = (host: string) => adminPage.getByRole('row').filter({ hasText: host });

    await expect(rowFor(signed.hostId)).toContainText('Signed');
    await expect(rowFor(unsigned.hostId)).toContainText('Unsigned');
    await expect(adminPage.getByText('Pending', { exact: true })).toHaveCount(0);
  });

  test('refresh keeps the server list', async ({ adminPage, sdk }) => {
    const m = await seedManifest(sdk, unique('refresh-host'));

    await adminPage.goto('/attestation');
    await expect(adminPage.getByText(m.hostId).first()).toBeVisible();
    await adminPage.getByRole('button', { name: /refresh/i }).click();
    await expect(adminPage.getByText(m.hostId).first()).toBeVisible();
  });

  test('detail page shows the TPM quote of a built manifest', async ({ adminPage, sdk }) => {
    const m = await seedManifest(sdk, unique('quote-host'));

    await adminPage.goto(`/attestation/${m.id}`);

    await expect(adminPage.getByText(m.hostId).first()).toBeVisible();
    await expect(adminPage.getByRole('heading', { name: 'TPM Quote' })).toBeVisible();
  });

  test('detail page of an unknown manifest reports not found', async ({ adminPage }) => {
    await adminPage.goto(`/attestation/${unique('non-existent')}`);
    await expect(adminPage.getByText(/not found|error|failed/i).first()).toBeVisible();
  });

  test('manifests page lists built manifests', async ({ adminPage, sdk }) => {
    const m = await seedManifest(sdk, unique('manifest-host'));

    await adminPage.goto('/attestation/manifests');

    await expect(adminPage.getByRole('heading', { name: /attestation manifests/i })).toBeVisible();
    await expect(adminPage.getByText('Total Manifests')).toBeVisible();
    await expect(adminPage.getByText(m.hostId).first()).toBeVisible();
    await expect(adminPage.getByRole('button', { name: /create manifest/i })).toBeVisible();
  });

  test('quotes page lists the quote of a built manifest', async ({ adminPage, sdk }) => {
    const m = await seedManifest(sdk, unique('quotes-host'));

    await adminPage.goto('/attestation/quotes');

    await expect(adminPage.getByRole('heading', { name: /tpm quotes/i })).toBeVisible();
    await expect(adminPage.getByText('Total Quotes')).toBeVisible();
    await expect(adminPage.getByText(m.hostId).first()).toBeVisible();
    await expect(adminPage.getByText('Verified', { exact: true })).toHaveCount(0);
  });

  test('event logs page renders statistics', async ({ adminPage, sdk }) => {
    await seedManifest(sdk, unique('eventlog-host'));

    await adminPage.goto('/attestation/eventlogs');

    await expect(adminPage.getByRole('heading', { name: /tpm event logs/i })).toBeVisible();
    const main = adminPage.locator('main');
    await expect(main.getByText('Total Events')).toBeVisible();
    await expect(main.getByText('PCRs Used')).toBeVisible();
    await expect(adminPage.getByRole('button', { name: /export/i })).toBeVisible();
  });

  test('verify page renders statistics and the run button', async ({ adminPage, sdk }) => {
    await seedManifest(sdk, unique('verify-host'));

    await adminPage.goto('/attestation/verify');

    await expect(adminPage.getByRole('heading', { name: /attestation verification/i })).toBeVisible();
    await expect(adminPage.getByText('Total Verifications')).toBeVisible();
    await expect(adminPage.getByRole('button', { name: /run verification/i })).toBeVisible();
    await expect(adminPage.getByText('Verification Results')).toBeVisible();
  });
});

test.describe('Access Control (real server)', () => {
  test('redirects unauthenticated users from TPM pages', async ({ page }) => {
    await page.goto('/tpm/status');
    await expect(page).toHaveURL(/\/auth\/webauthn/);
  });

  test('redirects unauthenticated users from attestation pages', async ({ page }) => {
    await page.goto('/attestation');
    await expect(page).toHaveURL(/\/auth\/webauthn/);
  });
});

test.describe('Navigation (real server)', () => {
  for (const url of ['/tpm/status', '/tpm/keys', '/tpm/pcrs', '/tpm/nvram', '/tpm/seal']) {
    test(`opens ${url} without a login redirect`, async ({ adminPage }) => {
      await adminPage.goto(url);
      await expect(adminPage.locator('h1').first()).toBeVisible();
      expect(/\/auth\/webauthn/.test(adminPage.url())).toBe(false);
    });
  }

  for (const url of [
    '/attestation',
    '/attestation/manifests',
    '/attestation/quotes',
    '/attestation/eventlogs',
    '/attestation/verify',
  ]) {
    test(`opens ${url} without a login redirect`, async ({ adminPage }) => {
      await adminPage.goto(url);
      await expect(adminPage.locator('h1').first()).toBeVisible();
      expect(/\/auth\/webauthn/.test(adminPage.url())).toBe(false);
    });
  }
});
