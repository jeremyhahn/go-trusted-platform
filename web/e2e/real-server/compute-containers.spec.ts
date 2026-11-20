import type { Page, Request, Response } from '@playwright/test';
import { test, expect } from './fixtures';

/**
 * Container detail, exec, metrics and attestation pages (#1721), and the VM
 * attestation verify action on the VM detail page, against the real-server
 * harness (#2035).
 *
 * The containers and VMs are whatever the harness compute service lists; the
 * SDK reads them, and each case asserts the page renders the server's answer.
 * A case that needs a container or a VM skips when the harness lists none;
 * cases that need a scripted daemon answer (fixed metrics, a verified quote,
 * a failure on the second call) are gaps in the PR body.
 */

const COMPUTE = '/api/v1/compute';

function path(url: string): string {
  return new URL(url).pathname;
}

/** Records every non-GET compute call the page makes. */
function recordMutations(page: Page): Array<{ method: string; path: string }> {
  const calls: Array<{ method: string; path: string }> = [];
  page.on('request', (r: Request) => {
    if (r.method() !== 'GET' && path(r.url()).startsWith(COMPUTE)) calls.push({ method: r.method(), path: path(r.url()) });
  });
  return calls;
}

/** The message of a platform error envelope, in either of its two shapes. */
async function errorText(r: Response): Promise<string> {
  const b = (await r.json().catch(() => null)) as { error?: string | { message?: string } } | null;
  if (typeof b?.error === 'string') return b.error;
  return b?.error?.message ?? '';
}

/** Opens a static-export detail page (`/compute/{kind}/{id}`) and returns its GET of the resource. */
async function openDetail(page: Page, kind: 'containers' | 'vms', id: string): Promise<Response> {
  const read = page.waitForResponse(
    (r) => r.request().method() === 'GET' && path(r.url()) === `${COMPUTE}/${kind}/${encodeURIComponent(id)}`
  );
  await page.goto(`/compute/${kind}/__placeholder__/`);
  await page.waitForLoadState('networkidle');
  await page.evaluate(([k, i]) => window.history.pushState(null, '', `/compute/${k}/${i}/`), [kind, id]);
  return read;
}

interface ListedContainer {
  id: string;
  name: string;
  image: string;
}

interface ContainerLister {
  compute: {
    listContainers(): Promise<{
      success: boolean;
      data?: { containers?: Array<{ id: string; name?: string; image?: string; config?: { name?: string; image?: string } }> };
    }>;
  };
}

async function firstContainer(sdk: ContainerLister): Promise<ListedContainer | null> {
  const res = await sdk.compute.listContainers().catch(() => ({ success: false, data: undefined }));
  const c = res.data?.containers?.[0];
  if (!res.success || !c) return null;
  return { id: c.id, name: c.config?.name ?? c.name ?? c.id, image: c.config?.image ?? c.image ?? '' };
}

test.describe('Compute containers: detail, exec, metrics and attestation (#1721), real server', () => {
  test('GetContainer for an unknown ID shows the load failure, and no controls', async ({ adminPage }) => {
    const id = `e2e-absent-${Date.now()}`;
    const res = await openDetail(adminPage, 'containers', id);
    expect(res.ok()).toBe(false);
    await expect(adminPage.getByText(/Failed to load container/)).toBeVisible();
    await expect(adminPage.getByRole('button', { name: 'Attest' })).toHaveCount(0);
    await expect(adminPage.getByLabel('Command')).toHaveCount(0);
  });

  test('GetContainer shows the container the server lists', async ({ adminPage, sdk }) => {
    const c = await firstContainer(sdk);
    test.skip(!c, 'the harness lists no container');
    const res = await openDetail(adminPage, 'containers', c!.id);
    expect(res.ok()).toBe(true);
    await expect(adminPage.getByRole('heading', { name: c!.name })).toBeVisible();
    if (c!.image) await expect(adminPage.getByText(c!.image).first()).toBeVisible();
    await expect(adminPage.getByTestId('container-metrics')).toBeVisible();
  });

  test('ExecContainer sends nothing before the confirm, then the parsed command', async ({ adminPage, sdk }) => {
    const c = await firstContainer(sdk);
    test.skip(!c, 'the harness lists no container');
    const calls = recordMutations(adminPage);
    await openDetail(adminPage, 'containers', c!.id);
    await adminPage.getByLabel('Command').fill(`sh -c 'echo hello' ""`);
    await adminPage.getByRole('button', { name: 'Run' }).click();

    const dialog = adminPage.getByRole('dialog');
    await expect(dialog.getByText('Run command in container?')).toBeVisible();
    expect(calls).toEqual([]);

    const answer = adminPage.waitForResponse(
      (r) => r.request().method() === 'POST' && path(r.url()).endsWith(`/containers/${encodeURIComponent(c!.id)}/exec`)
    );
    await dialog.getByRole('button', { name: 'Confirm' }).click();
    const res = await answer;
    expect(res.request().postDataJSON()).toMatchObject({ command: ['sh', '-c', 'echo hello', ''] });

    const result = adminPage.getByTestId('exec-result');
    if (res.ok()) {
      await expect(result.getByText(/Exit code:/)).toBeVisible();
    } else {
      await expect(result).toContainText('Exec failed');
      await expect(result.getByText(/Exit code/)).toHaveCount(0);
    }
  });

  test('ExecContainer is not sent when the confirm dialog is cancelled', async ({ adminPage, sdk }) => {
    const c = await firstContainer(sdk);
    test.skip(!c, 'the harness lists no container');
    const calls = recordMutations(adminPage);
    await openDetail(adminPage, 'containers', c!.id);
    await adminPage.getByLabel('Command').fill('rm -rf /tmp/x');
    await adminPage.getByRole('button', { name: 'Run' }).click();
    await adminPage.getByRole('dialog').getByRole('button', { name: 'Cancel' }).click();

    await expect(adminPage.getByRole('dialog')).toBeHidden();
    await expect(adminPage.getByTestId('exec-result')).toHaveCount(0);
    expect(calls).toEqual([]);
  });

  test('AttestContainer sends an empty body after the confirm and shows the answer', async ({ adminPage, sdk }) => {
    const c = await firstContainer(sdk);
    test.skip(!c, 'the harness lists no container');
    const calls = recordMutations(adminPage);
    await openDetail(adminPage, 'containers', c!.id);
    await adminPage.getByRole('button', { name: 'Attest' }).click();

    const dialog = adminPage.getByRole('dialog');
    await expect(dialog.getByText('Attest container?')).toBeVisible();
    expect(calls).toEqual([]);
    const answer = adminPage.waitForResponse(
      (r) => r.request().method() === 'POST' && path(r.url()).endsWith(`/containers/${encodeURIComponent(c!.id)}/attest`)
    );
    await dialog.getByRole('button', { name: 'Confirm' }).click();
    const res = await answer;
    // The daemon takes no caller nonce, PCR selection or bank: none is sent.
    expect(res.request().postDataJSON()).toEqual({});

    const result = adminPage.getByTestId('attest-result');
    if (res.ok()) {
      await expect(result.getByText('Not bound to a caller nonce; the daemon selects the PCRs.')).toBeVisible();
    } else {
      await expect(result.getByText(/Attestation failed/)).toBeVisible();
    }
  });

  test('VerifyVMAttestation verifies the quote of the nonce it sent', async ({ adminPage, sdk }) => {
    const vms = await sdk.compute.listVMs().catch(() => ({ success: false, data: undefined }));
    const vm = (vms.data as { vms?: Array<{ id: string }> } | undefined)?.vms?.[0];
    test.skip(!vm, 'the harness lists no VM');

    const res = await openDetail(adminPage, 'vms', vm!.id);
    expect(res.ok()).toBe(true);
    await adminPage.getByRole('button', { name: 'Verify Attestation' }).click();
    const dialog = adminPage.getByRole('dialog');
    await expect(dialog.getByText('Verify VM attestation?')).toBeVisible();

    const attest = adminPage.waitForResponse(
      (r) => r.request().method() === 'POST' && path(r.url()).endsWith(`/vms/${encodeURIComponent(vm!.id)}/attest`)
    );
    await dialog.getByRole('button', { name: 'Confirm' }).click();
    const a = await attest;
    const nonce = (a.request().postDataJSON() as { nonce?: string }).nonce ?? '';
    expect(nonce).not.toBe('');

    const verdict = adminPage.getByTestId('vm-verify-result');
    if (!a.ok()) {
      const message = await errorText(a);
      await expect(verdict).toContainText(/failed/i);
      if (message) await expect(verdict).toContainText(message);
      return;
    }
    const verify = await adminPage.waitForRequest(
      (r) => r.method() === 'POST' && path(r.url()).endsWith(`/vms/${encodeURIComponent(vm!.id)}/attest/verify`)
    );
    expect(verify.postDataJSON()).toMatchObject({ nonce });
    await expect(verdict).toBeVisible();
    // The page never claims an appraisal it did not run.
    await expect(verdict.getByText('Attestation verified', { exact: true })).toHaveCount(0);
  });

  test('the containers list links each listed container to its detail page', async ({ adminPage, sdk }) => {
    const c = await firstContainer(sdk);
    test.skip(!c, 'the harness lists no container');
    await adminPage.goto('/compute/containers');
    await adminPage.getByRole('link', { name: c!.name }).first().click();
    await expect(adminPage).toHaveURL(new RegExp(`/compute/containers/${c!.id}/?$`));
    await expect(adminPage.getByRole('heading', { name: c!.name })).toBeVisible();
  });
});
