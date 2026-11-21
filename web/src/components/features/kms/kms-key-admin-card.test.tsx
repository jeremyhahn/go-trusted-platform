import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { KmsKeyAdminCard } from './kms-key-admin-card';

// #2057: the KMS key admin card sets a key's status through the API client at
// the served PUT /v1/kms/keys/{name}/status route. Every status but ENABLED
// asks first, because a disabled or compromised key refuses every operation.

const STATUS_PATH = 'PUT /api/v1/kms/keys/app-key/status';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function typeKey(value: string) {
  fireEvent.change(screen.getByLabelText('Key name'), { target: { value } });
}

function pickStatus(value: string) {
  fireEvent.change(screen.getByLabelText('New status'), { target: { value } });
}

async function click(name: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name }));
  });
}

describe('KmsKeyAdminCard status', () => {
  it('enables a key at once', async () => {
    const sent = stubControlPlane({
      [STATUS_PATH]: ok({ key_id: 'app-key', version: 2, status: 'ENABLED' }),
    });
    render(withControlPlane(<KmsKeyAdminCard />));

    typeKey('app-key');
    await click('Update status');

    const toast = await screen.findByText('Key status updated: app-key v2 is ENABLED');
    expect(toast.getAttribute('data-variant')).toBe('success');
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(sent).toEqual([
      { method: 'PUT', path: '/api/v1/kms/keys/app-key/status', body: { status: 'ENABLED' } },
    ]);
  });

  it('disables a key only after the confirm', async () => {
    const sent = stubControlPlane({
      [STATUS_PATH]: ok({ key_id: 'app-key', version: 2, status: 'DISABLED' }),
    });
    render(withControlPlane(<KmsKeyAdminCard />));

    typeKey('app-key');
    pickStatus('DISABLED');
    await click('Update status');

    const dialog = await screen.findByRole('dialog');
    expect(dialog.textContent).toContain('Set app-key to DISABLED?');
    expect(sent).toEqual([]);

    await click('Set status');

    await screen.findByText('Key status updated: app-key v2 is DISABLED');
    expect(sent).toEqual([
      { method: 'PUT', path: '/api/v1/kms/keys/app-key/status', body: { status: 'DISABLED' } },
    ]);
  });

  it('sends nothing on Cancel', async () => {
    const sent = stubControlPlane({});
    render(withControlPlane(<KmsKeyAdminCard />));

    typeKey('app-key');
    pickStatus('COMPROMISED');
    await click('Update status');
    await screen.findByRole('dialog');
    await click('Cancel');

    expect(sent).toEqual([]);
  });

  it('sends the version when given', async () => {
    const sent = stubControlPlane({
      [STATUS_PATH]: ok({ key_id: 'app-key', version: 3, status: 'ENABLED' }),
    });
    render(withControlPlane(<KmsKeyAdminCard />));

    typeKey('app-key');
    fireEvent.change(screen.getByLabelText('Version (optional)'), { target: { value: '3' } });
    await click('Update status');

    await screen.findByText('Key status updated: app-key v3 is ENABLED');
    expect(sent).toEqual([
      {
        method: 'PUT',
        path: '/api/v1/kms/keys/app-key/status',
        body: { status: 'ENABLED', version: 3 },
      },
    ]);
  });

  it('shows a status refusal verbatim', async () => {
    stubControlPlane({ [STATUS_PATH]: refused(404, 'key not found: app-key') });
    render(withControlPlane(<KmsKeyAdminCard />));

    typeKey('app-key');
    await click('Update status');

    const toast = await screen.findByText('Status update failed: key not found: app-key');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
  });
});
