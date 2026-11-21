import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import NewGroupPage from './page';

// #2053: the new-group page creates the group through the SDK's
// IAMService.createGroup (POST /iam/tenants/{tenant}/groups); a refusal
// reaches the operator with the server's own message.

const push = vi.fn();

vi.mock('next/navigation', () => ({
  usePathname: () => '/iam/groups/new',
  useRouter: () => ({ push, back: vi.fn() }),
}));

const authResult = { tenantId: 't-1', isLoading: false };

vi.mock('@/contexts/AuthContext', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/contexts/AuthContext')>()),
  useAuth: () => authResult,
}));

const CREATE_PATH = 'POST /api/v1/iam/tenants/t-1/groups';

function toasts(prefix: string) {
  return screen.queryAllByTestId('toast').filter((t) => t.textContent?.startsWith(prefix));
}

async function fillAndCreate() {
  fireEvent.change(screen.getByLabelText('Name *'), { target: { value: 'Eng Team' } });
  fireEvent.change(screen.getByLabelText('Description'), { target: { value: 'Engineering' } });
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: 'Create Group' }));
  });
}

describe('NewGroupPage CreateGroup', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    push.mockReset();
  });

  it('sends the group through POST /iam/tenants/{tenant}/groups and toasts Group created', async () => {
    const sent = stubControlPlane({
      [CREATE_PATH]: ok({ group: { id: 'eng-team', name: 'Eng Team', description: 'Engineering' } }),
    });
    render(withControlPlane(<NewGroupPage />));

    await fillAndCreate();

    await waitFor(() => expect(sent.some((r) => r.method === 'POST')).toBe(true));
    const post = sent.find((r) => r.method === 'POST');
    expect(post?.path).toBe('/api/v1/iam/tenants/t-1/groups');
    expect(post?.body).toMatchObject({ tenantId: 't-1', id: 'eng-team', name: 'Eng Team', description: 'Engineering' });
    await waitFor(() => expect(toasts('Group created').length).toBeGreaterThan(0));
    expect(push).toHaveBeenCalledWith('/iam/groups');
  });

  it("shows a refused create with the server's message as a destructive toast", async () => {
    stubControlPlane({ [CREATE_PATH]: refused(409, 'group eng-team already exists') });
    render(withControlPlane(<NewGroupPage />));

    await fillAndCreate();

    const toast = await screen.findByText('Failed to create group: group eng-team already exists');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
    expect(push).not.toHaveBeenCalled();
  });
});
