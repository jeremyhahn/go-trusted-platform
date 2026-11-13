/**
 * VM operations on the VM detail page and the Migrations page (#1727,
 * slice 7 of #1665). Every compute call is answered by mockVMOperationsApi.
 */
import { test, expect, Page } from '@playwright/test'
import { createTenantOwnerSession } from './fixtures/auth-setup'
import { mockTenantApi, mockVMOperationsApi } from './fixtures/api-mock'

const VM_ID = 'vm-ops-1'

async function openVM(page: Page, state = 'VM_STATE_RUNNING') {
  const api = await mockVMOperationsApi(page, { vmId: VM_ID, vmName: 'ops-vm', state })
  await mockTenantApi(page)
  await page.goto(`/compute/vms/${VM_ID}`)
  await expect(page.getByRole('heading', { name: 'ops-vm' })).toBeVisible()
  return api
}

function lastCall(api: Awaited<ReturnType<typeof mockVMOperationsApi>>, method: string, path: string) {
  return api
    .calls()
    .filter((c) => c.method === method && c.path === path)
    .pop()
}

test.describe('Compute VM operations', () => {
  test.beforeEach(async ({ page }) => {
    await createTenantOwnerSession(page.context())
  })

  test('GetVM shows the VM detail', async ({ page }) => {
    const api = await openVM(page)
    await expect(page.getByText('Virtual Machine Details')).toBeVisible()
    await expect(page.getByText('running', { exact: true })).toBeVisible()
    expect(lastCall(api, 'GET', `/vms/${VM_ID}`)).toBeTruthy()
  })

  test('SuspendVM suspends a running VM', async ({ page }) => {
    const api = await openVM(page)
    await page.getByRole('button', { name: 'Suspend' }).click()
    await expect(page.getByRole('button', { name: 'Resume' })).toBeVisible()
    expect(lastCall(api, 'POST', `/vms/${VM_ID}/suspend`)).toBeTruthy()
  })

  test('ResumeVM resumes a suspended VM', async ({ page }) => {
    const api = await openVM(page, 'VM_STATE_PAUSED')
    await page.getByRole('button', { name: 'Resume' }).click()
    await expect(page.getByRole('button', { name: 'Suspend' })).toBeVisible()
    expect(lastCall(api, 'POST', `/vms/${VM_ID}/resume`)).toBeTruthy()
  })

  test('the 5 s refresh keeps VM operations forms and dialogs', async ({ page }) => {
    const api = await openVM(page)
    await page.getByLabel('Snapshot name').fill('kept-across-refresh')
    await page.getByLabel('Destination host').fill('dest-node')
    await page.getByRole('button', { name: 'Migrate VM' }).click()
    const dialog = page.getByRole('dialog')
    await expect(dialog).toContainText('Migrate this VM to dest-node?')
    const fetchesBefore = api.calls().filter((c) => c.method === 'GET' && c.path === `/vms/${VM_ID}`).length
    await page.waitForTimeout(6000)
    const fetchesAfter = api.calls().filter((c) => c.method === 'GET' && c.path === `/vms/${VM_ID}`).length
    expect(fetchesAfter).toBeGreaterThan(fetchesBefore)
    await expect(dialog).toBeVisible()
    await expect(dialog).toContainText('Migrate this VM to dest-node?')
    await expect(page.getByLabel('Snapshot name')).toHaveValue('kept-across-refresh')
  })

  test('AttestVM shows the attestation result', async ({ page }) => {
    const api = await openVM(page)
    await page.getByRole('button', { name: 'Attest VM' }).click()
    const card = page.getByTestId('vm-attestation')
    await expect(card).toContainText('Attestation collected')
    await expect(card).toContainText('PCR values: 2')
    await expect(card).toContainText('SHA256-RSAPSS')
    const call = lastCall(api, 'POST', `/vms/${VM_ID}/attest`)
    expect((call?.body as { nonce?: string }).nonce).toBeTruthy()
  })

  test('GetVMMetrics shows metrics', async ({ page }) => {
    const api = await openVM(page)
    await page.getByRole('button', { name: 'Load Metrics' }).click()
    const card = page.getByTestId('vm-live-metrics')
    await expect(card).toContainText('CPU: 42%')
    await expect(card).toContainText('Memory used: 1536 MB')
    await expect(card).toContainText('Uptime: 3600 s')
    expect(lastCall(api, 'GET', `/vms/${VM_ID}/metrics`)).toBeTruthy()
  })

  test('AttachDisk attaches a disk', async ({ page }) => {
    const api = await openVM(page)
    await page.getByLabel('Disk path').fill('/var/lib/disks/data.qcow2')
    await page.getByLabel('Size GB', { exact: true }).fill('25')
    await page.getByRole('button', { name: 'Attach Disk' }).click()
    await expect(page.getByTestId('vm-disk-result')).toHaveText(/^Attached \/var\/lib\/disks\/data\.qcow2 as disk-/)
    const call = lastCall(api, 'POST', `/vms/${VM_ID}/disks`)
    expect(call?.body).toEqual({
      disk: { id: expect.stringMatching(/^disk-[0-9a-f]{16}$/), path: '/var/lib/disks/data.qcow2', sizeGb: 25 },
    })
  })

  test('AttachDisk then ResizeDisk and DetachDisk use the attached ID', async ({ page }) => {
    const api = await openVM(page)
    await page.getByLabel('Disk path').fill('/var/lib/disks/data.qcow2')
    await page.getByRole('button', { name: 'Attach Disk' }).click()
    await expect(page.getByTestId('vm-disk-result')).toHaveText(/^Attached \/var\/lib\/disks\/data\.qcow2 as disk-/)
    const id = await page.getByLabel('Disk ID').inputValue()
    expect(id).toMatch(/^disk-[0-9a-f]{16}$/)
    await page.getByLabel('New size GB').fill('64')
    await page.getByRole('button', { name: 'Resize Disk' }).click()
    await expect(page.getByTestId('vm-disk-result')).toHaveText(`Resized ${id} to 64 GB`)
    expect(lastCall(api, 'PATCH', `/vms/${VM_ID}/disks/${id}`)?.body).toEqual({ newSizeGb: 64 })
    await page.getByRole('button', { name: 'Detach Disk' }).click()
    await page.getByRole('dialog').getByRole('button', { name: 'Confirm' }).click()
    await expect(page.getByTestId('vm-disk-result')).toHaveText(`Detached ${id}`)
    expect(lastCall(api, 'DELETE', `/vms/${VM_ID}/disks/${id}`)).toBeTruthy()
  })

  test('DetachDisk detaches a disk after confirm', async ({ page }) => {
    const api = await openVM(page)
    await page.getByLabel('Disk ID').fill('disk-2')
    await page.getByRole('button', { name: 'Detach Disk' }).click()
    const dialog = page.getByRole('dialog')
    await expect(dialog).toContainText('Detach disk disk-2 from this VM?')
    expect(lastCall(api, 'DELETE', `/vms/${VM_ID}/disks/disk-2`)).toBeFalsy()
    await dialog.getByRole('button', { name: 'Confirm' }).click()
    await expect(page.getByTestId('vm-disk-result')).toHaveText('Detached disk-2')
    expect(lastCall(api, 'DELETE', `/vms/${VM_ID}/disks/disk-2`)).toBeTruthy()
  })

  test('ResizeDisk resizes a disk', async ({ page }) => {
    const api = await openVM(page)
    await page.getByLabel('Disk ID').fill('disk-2')
    await page.getByLabel('New size GB').fill('64')
    await page.getByRole('button', { name: 'Resize Disk' }).click()
    await expect(page.getByTestId('vm-disk-result')).toHaveText('Resized disk-2 to 64 GB')
    expect(lastCall(api, 'PATCH', `/vms/${VM_ID}/disks/disk-2`)?.body).toEqual({ newSizeGb: 64 })
  })

  test('CreateSnapshot creates a snapshot', async ({ page }) => {
    const api = await openVM(page)
    await page.getByLabel('Snapshot name').fill('before-upgrade')
    await page.getByRole('button', { name: 'Take Snapshot' }).click()
    await expect(page.getByTestId('vm-snapshot-detail')).toContainText('before-upgrade (snap-new)')
    await expect(page.getByLabel('Snapshot ID')).toHaveValue('snap-new')
    expect(lastCall(api, 'POST', `/vms/${VM_ID}/snapshots`)?.body).toEqual({
      config: { name: 'before-upgrade' },
    })
  })

  test('GetSnapshot shows snapshot detail', async ({ page }) => {
    const api = await openVM(page)
    await page.getByLabel('Snapshot ID').fill('snap-7')
    await page.getByRole('button', { name: 'Get Snapshot' }).click()
    const detail = page.getByTestId('vm-snapshot-detail')
    await expect(detail).toContainText('stored-snap-7 (snap-7)')
    await expect(detail).toContainText('Size: 4096 bytes')
    expect(lastCall(api, 'GET', `/vms/${VM_ID}/snapshots/snap-7`)).toBeTruthy()
  })

  test('MigrateVM migrates after confirm', async ({ page }) => {
    const api = await openVM(page)
    await page.getByLabel('Destination host').fill('dest-node')
    await page.getByRole('button', { name: 'Migrate VM' }).click()
    const dialog = page.getByRole('dialog')
    await expect(dialog).toContainText('Migrate this VM to dest-node?')
    await dialog.getByRole('button', { name: 'Confirm' }).click()
    await expect(page.getByTestId('vm-migrate-result')).toHaveText('Migration to dest-node started')
    expect(lastCall(api, 'POST', `/vms/${VM_ID}/migrate`)?.body).toEqual({
      destinationHost: 'dest-node',
      liveMigration: false,
    })
  })

  test('PrepareMigration prepares a receiver', async ({ page }) => {
    const api = await mockVMOperationsApi(page, { vmId: VM_ID })
    await mockTenantApi(page)
    await page.goto('/compute/migrations')
    await expect(page.getByRole('heading', { name: 'VM Migrations' })).toBeVisible()
    await page.getByLabel('Guest name').fill('ops-vm')
    await page.getByLabel('Mode', { exact: true }).selectOption('cold')
    await expect(page.getByRole('button', { name: 'Prepare Migration' })).toBeDisabled()
    await page.getByLabel('Memory MB').fill('4096')
    await page.getByLabel('CPUs').fill('4')
    await page.getByLabel('Disk size').fill('40G')
    await page.getByLabel('Boot mode').fill('uefi')
    await page.getByLabel('Arch').selectOption('aarch64')
    await page.getByLabel('Secure boot').check()
    await page.getByLabel('TPM').check()
    await page.getByRole('button', { name: 'Prepare Migration' }).click()
    const receiver = page.getByTestId('migration-receiver')
    await expect(receiver).toContainText('Receiver: rx-42')
    await expect(receiver).toContainText('Port: 49152')
    await expect(page.getByLabel('Receiver ID')).toHaveValue('rx-42')
    expect(lastCall(api, 'POST', '/migrations/prepare')?.body).toEqual({
      vmName: 'ops-vm',
      mode: 'cold',
      spec: {
        memoryMb: 4096,
        cpus: 4,
        diskSize: '40G',
        bootMode: 'uefi',
        arch: 'aarch64',
        secureBoot: true,
        enableKvm: true,
        tpmEnabled: true,
        networkMode: 'bridge',
      },
    })
  })

  test('FinalizeMigration finalizes a receiver', async ({ page }) => {
    const api = await mockVMOperationsApi(page, { vmId: VM_ID })
    await mockTenantApi(page)
    await page.goto('/compute/migrations')
    await page.getByLabel('Guest name').fill('ops-vm')
    await page.getByLabel('Receiver ID').fill('rx-42')
    await page.getByRole('button', { name: 'Commit Migration' }).click()
    const dialog = page.getByRole('dialog')
    await expect(dialog).toContainText('Register and resume the VM received by rx-42?')
    await dialog.getByRole('button', { name: 'Confirm' }).click()
    await expect(page.getByTestId('migration-finalize-result')).toHaveText(
      'Receiver rx-42 committed: VM ops-vm registered',
    )
    expect(lastCall(api, 'POST', '/migrations/rx-42/finalize')?.body).toEqual({ commit: true })
    expect(lastCall(api, 'GET', '/vms')).toBeTruthy()
  })

  test('the sidebar lists the Migrations page', async ({ page }) => {
    await mockVMOperationsApi(page, { vmId: VM_ID })
    await mockTenantApi(page)
    await page.goto('/compute/migrations')
    await expect(page.getByRole('link', { name: 'Migrations' })).toBeVisible()
  })
})
