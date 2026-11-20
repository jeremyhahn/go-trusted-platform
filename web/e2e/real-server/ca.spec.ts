// Real-server spec for the CAService row (#2041, epic #1665): GetCAInfo,
// InitCA, InstallCACertificates, UninstallCACertificates, SignCSR and
// VerifyCertificate. State is seeded through the SDK client the harness
// hands out, never through route mocks, and every assertion compares the
// page with what the server returned.
import { test, expect } from './fixtures';

type Loose = Record<string, unknown>;

/** The SDK answers either the body or an envelope with `data`; take the body. */
function body(res: unknown): Loose {
  const r = (res ?? {}) as Loose;
  return ((r.data as Loose | undefined) ?? r) as Loose;
}

function str(v: unknown): string {
  return typeof v === 'string' ? v : v === undefined || v === null ? '' : String(v);
}

function caInfoOf(res: unknown): Loose {
  const b = body(res);
  return ((b.caInfo ?? b.ca_info ?? b) as Loose) ?? {};
}

/** Wrap base64 DER into PEM, as the verify page expects pasted text. */
function toPem(b64: string): string {
  if (b64.startsWith('-----BEGIN')) return b64;
  const lines = b64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----\n`;
}

test.describe('CA overview (GetCAInfo)', () => {
  test('shows the identity and defaults the server reports', async ({ adminPage, sdk }) => {
    const info = caInfoOf(await sdk.ca.getInfo());
    const commonName = str(info.commonName ?? info.common_name);
    const algorithm = str(info.defaultAlgorithm ?? info.default_algorithm);
    const validity = info.defaultValidityDays ?? info.default_validity_days;
    expect(commonName).not.toBe('');

    await adminPage.goto('/ca');
    await expect(adminPage.getByTestId('ca-common-name')).toHaveText(commonName);
    await expect(adminPage.getByTestId('ca-default-algorithm')).toHaveText(algorithm);
    if (validity !== undefined) {
      await expect(adminPage.getByTestId('ca-default-validity')).toHaveText(`${validity} days`);
    }
    const root = (info.rootCert ?? info.root_cert) as Loose | undefined;
    if (root?.serial) {
      await expect(adminPage.getByTestId('ca-root-cert')).toContainText(str(root.serial));
    }
  });
});

test.describe('CA lifecycle controls (InitCA, InstallCACertificates, UninstallCACertificates)', () => {
  // The daemon serves no REST route for these three: they run at daemon
  // start (LoadOrInitCA) with the SO and user PINs. The page shows each
  // control disabled with the reason, and pressing it sends nothing.
  for (const [id, label] of [
    ['ca-init-control', 'Initialize CA'],
    ['ca-install-control', 'Install CA certificates'],
    ['ca-uninstall-control', 'Uninstall CA certificates'],
  ] as const) {
    test(`${label} is gated off with its reason`, async ({ adminPage }) => {
      const writes: string[] = [];
      adminPage.on('request', (req) => {
        if (req.method() !== 'GET' && req.url().includes('/api/v1/ca')) writes.push(req.url());
      });
      await adminPage.goto('/ca');
      const control = adminPage.getByTestId(id);
      await expect(control).toBeDisabled();
      await expect(control).toHaveText(label);
      await expect(adminPage.getByTestId(`${id}-reason`)).toContainText('Not available');
      await control.click({ force: true });
      expect(writes).toEqual([]);
    });
  }
});

test.describe('Verify certificate (VerifyCertificate)', () => {
  test('a certificate the CA issued verifies as the server says', async ({ adminPage, sdk, tenant }) => {
    const issued = body(
      await sdk.ca.issueCertificate({
        commonName: `e2e-verify-${tenant.id}-${Date.now()}`,
        validDays: 1,
      } as never),
    );
    const cert = (issued.certificate ?? issued) as Loose;
    const pem = toPem(str(cert.pem));
    expect(pem).toContain('BEGIN CERTIFICATE');

    const verdict = body(
      await sdk.ca.verifyCertificate({
        certificatePem: str(cert.pem).startsWith('-----BEGIN') ? btoa(str(cert.pem)) : str(cert.pem),
        verifyRevocation: true,
      } as never),
    );

    await adminPage.goto('/ca/verify');
    await adminPage.locator('#certificate-pem').fill(pem);
    await adminPage.getByRole('button', { name: 'Verify' }).click();
    await expect(adminPage.getByTestId('verify-result')).toHaveText(
      verdict.valid ? 'Certificate is valid' : 'Certificate is not valid',
    );
  });

  test('a malformed certificate shows the server refusal and no verdict', async ({ adminPage }) => {
    await adminPage.goto('/ca/verify');
    await adminPage.locator('#certificate-pem').fill('-----BEGIN CERTIFICATE-----\nnot-a-cert\n-----END CERTIFICATE-----');
    await adminPage.getByRole('button', { name: 'Verify' }).click();
    await expect(adminPage.getByTestId('verify-result')).toHaveCount(0);
  });
});

test.describe('Sign CSR (SignCSR)', () => {
  test('a malformed CSR is refused by the server and no certificate is shown', async ({ adminPage, sdk }) => {
    let refused = false;
    try {
      const res = (await sdk.ca.signCSR({ csrPem: 'not-a-csr' } as never)) as unknown as Loose;
      refused = res.success === false || Boolean(res.error);
    } catch {
      refused = true;
    }
    expect(refused).toBe(true);

    await adminPage.goto('/ca/sign');
    await adminPage.locator('#csr-pem').fill('-----BEGIN CERTIFICATE REQUEST-----\nnot-a-csr\n-----END CERTIFICATE REQUEST-----');
    await adminPage.locator('#platform-token').fill('not-a-token');
    await adminPage.getByRole('button', { name: 'Sign CSR' }).click();
    await expect(adminPage.getByTestId('signed-serial')).toHaveCount(0);
    await expect(adminPage.locator('.text-destructive').first()).toBeVisible();
  });

  test('the overview links reach the sign and verify pages', async ({ adminPage }) => {
    await adminPage.goto('/ca');
    await adminPage.getByTestId('ca-sign-link').click();
    await expect(adminPage).toHaveURL(/\/ca\/sign$/);
    await adminPage.goto('/ca');
    await adminPage.getByTestId('ca-verify-link').click();
    await expect(adminPage).toHaveURL(/\/ca\/verify$/);
  });
});
