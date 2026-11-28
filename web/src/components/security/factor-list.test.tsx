import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import type { AuthFactor } from '@/types/auth-factors';
import { FactorList } from './factor-list';

// #2033 item 5: the factor list's Edit label, Rotate and Remove controls
// follow the server's capabilities listing, so a factor write the server
// does not offer is disabled with its reason instead of sent.

const FACTOR_WRITE_OPS = [
  'PATCH /api/v1/users/{id}/factors/{factor_id}/label',
  'PUT /api/v1/users/{id}/factors/{factor_id}/rotate',
  'DELETE /api/v1/users/{id}/factors/{factor_id}',
];

// The server's capabilities listing: only the ops in enabled are offered.
function caps(enabled: string[]): Answer {
  const capabilities = enabled.map((op) => ({ op, kind: 'route', enabled: true }));
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.length });
}

function fido2(id: string, label: string): AuthFactor {
  return {
    id,
    user_id: 'user-1',
    type: 'fido2',
    label,
    metadata: {},
    registered_at: '2026-10-01T00:00:00Z',
    last_used_at: null,
    revoked_at: null,
    created_by: 'self',
  };
}

const a = fido2('factor-1', 'Desk YubiKey');
const b = fido2('factor-2', 'Travel YubiKey');

function renderList(factors: AuthFactor[]) {
  const onRotate = vi.fn();
  const onRemove = vi.fn();
  const onRelabel = vi.fn();
  render(
    withControlPlane(
      <FactorList factors={factors} loading={false} onRotate={onRotate} onRemove={onRemove} onRelabel={onRelabel} />,
    ),
  );
  return { onRotate, onRemove, onRelabel };
}

function button(name: string): HTMLButtonElement {
  return screen.getByRole('button', { name }) as HTMLButtonElement;
}

describe('FactorList capability gating', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('disables Edit label, Rotate and Remove when the server offers none of them', async () => {
    stubControlPlane({ 'GET /api/v1/capabilities': caps([]) });
    const { onRotate } = renderList([a, b]);

    await waitFor(() => expect(button('Rotate Desk YubiKey').getAttribute('data-capability-enabled')).toBe('false'));

    const editLabel = screen.getAllByRole('button', { name: 'Edit label' })[0] as HTMLButtonElement;
    for (const control of [button('Rotate Desk YubiKey'), button('Remove Desk YubiKey'), editLabel]) {
      expect(control.getAttribute('data-capability-enabled')).toBe('false');
      expect(control.disabled).toBe(true);
      expect(control.getAttribute('title')).toBeTruthy();
    }

    await act(async () => {
      fireEvent.click(button('Rotate Desk YubiKey'));
    });
    expect(onRotate).not.toHaveBeenCalled();
  });

  it('enables the controls the server offers', async () => {
    stubControlPlane({ 'GET /api/v1/capabilities': caps(FACTOR_WRITE_OPS) });
    const { onRotate } = renderList([a, b]);

    await waitFor(() => expect(button('Rotate Desk YubiKey').getAttribute('data-capability-enabled')).toBe('true'));

    const editLabel = screen.getAllByRole('button', { name: 'Edit label' })[0] as HTMLButtonElement;
    for (const control of [button('Rotate Desk YubiKey'), button('Remove Desk YubiKey'), editLabel]) {
      expect(control.getAttribute('data-capability-enabled')).toBe('true');
      expect(control.disabled).toBe(false);
    }

    await act(async () => {
      fireEvent.click(button('Rotate Desk YubiKey'));
    });
    expect(onRotate).toHaveBeenCalledTimes(1);
    expect(onRotate).toHaveBeenCalledWith(a);
  });

  it('keeps Remove disabled on the last factor even when offered', async () => {
    stubControlPlane({ 'GET /api/v1/capabilities': caps(FACTOR_WRITE_OPS) });
    renderList([a]);

    await waitFor(() => expect(button('Remove Desk YubiKey').getAttribute('data-capability-enabled')).toBe('true'));

    const remove = button('Remove Desk YubiKey');
    expect(remove.disabled).toBe(true);
    expect(remove.getAttribute('title')).toBe('Cannot remove the last factor');
  });
});
