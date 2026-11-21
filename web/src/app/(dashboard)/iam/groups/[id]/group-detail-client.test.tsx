import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from '@/test/control-plane-fetch';
import GroupDetailClient from './group-detail-client';

// #2053: the group page reads the group (GetGroup), edits its name and
// description (UpdateGroup) and adds or removes a member by user ID
// (AddGroupMember, RemoveGroupMember), all through the SDK's IAMService on
// the routed paths; a refusal reaches the operator with the server's message.

vi.mock('next/navigation', () => ({
  useParams: () => ({ id: 'g-1' }),
  usePathname: () => '/iam/groups/g-1',
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
}));

const authResult = { tenantId: 't-1', isLoading: false };

vi.mock('@/contexts/AuthContext', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/contexts/AuthContext')>()),
  useAuth: () => authResult,
}));

const GET_PATH = 'GET /api/v1/iam/tenants/t-1/groups/g-1';
const PUT_PATH = 'PUT /api/v1/iam/tenants/t-1/groups/g-1';
const ADD_PATH = 'POST /api/v1/iam/tenants/t-1/groups/g-1/members/u-7';
const REMOVE_PATH = 'DELETE /api/v1/iam/tenants/t-1/groups/g-1/members/u-7';

function storedGroup(name: string, description: string): Answer {
  return ok({ group: { id: 'g-1', tenantId: 't-1', name, description } });
}

function toasts(prefix: string) {
  return screen.queryAllByTestId('toast').filter((t) => t.textContent?.startsWith(prefix));
}

async function click(name: string) {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name }));
  });
}

function type(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

describe('GroupDetailClient', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('GetGroup: shows the name and description it reads', async () => {
    const sent = stubControlPlane({ [GET_PATH]: storedGroup('Eng Team', 'Engineering') });
    render(withControlPlane(<GroupDetailClient />));

    await screen.findByText('Eng Team');
    expect(screen.getByText('Engineering')).toBeTruthy();
    expect(sent).toContainEqual({ method: 'GET', path: '/api/v1/iam/tenants/t-1/groups/g-1', body: undefined });
  });

  it('UpdateGroup: sends the edited name and description, toasts and re-reads the group', async () => {
    const routes: Record<string, Answer> = {
      [GET_PATH]: storedGroup('Eng Team', 'Engineering'),
      [PUT_PATH]: storedGroup('Platform Team', 'Platform engineering'),
    };
    const sent = stubControlPlane(routes);
    render(withControlPlane(<GroupDetailClient />));

    await screen.findByText('Eng Team');
    expect((screen.getByLabelText('Group name') as HTMLInputElement).value).toBe('Eng Team');
    type('Group name', 'Platform Team');
    type('Group description', 'Platform engineering');
    routes[GET_PATH] = storedGroup('Platform Team', 'Platform engineering');
    await click('Save group');

    await waitFor(() => expect(sent.some((r) => r.method === 'PUT')).toBe(true));
    const put = sent.find((r) => r.method === 'PUT');
    expect(put?.path).toBe('/api/v1/iam/tenants/t-1/groups/g-1');
    expect(put?.body).toMatchObject({ name: 'Platform Team', description: 'Platform engineering' });
    await waitFor(() => expect(toasts('Group updated').length).toBeGreaterThan(0));
    const putAt = sent.findIndex((r) => r.method === 'PUT');
    await waitFor(() =>
      expect(sent.slice(putAt + 1).some((r) => r.method === 'GET' && r.path === '/api/v1/iam/tenants/t-1/groups/g-1')).toBe(
        true
      )
    );
  });

  it('AddGroupMember: posts the user ID in the path and toasts Member added', async () => {
    const sent = stubControlPlane({
      [GET_PATH]: storedGroup('Eng Team', 'Engineering'),
      [ADD_PATH]: ok({ success: true }),
    });
    render(withControlPlane(<GroupDetailClient />));

    await screen.findByText('Eng Team');
    type('Member user ID', 'u-7');
    await click('Add member');

    await waitFor(() =>
      expect(sent.some((r) => r.method === 'POST' && r.path === '/api/v1/iam/tenants/t-1/groups/g-1/members/u-7')).toBe(true)
    );
    await waitFor(() => expect(toasts('Member added').length).toBeGreaterThan(0));
  });

  it('RemoveGroupMember: deletes the member path and toasts Member removed', async () => {
    const sent = stubControlPlane({
      [GET_PATH]: storedGroup('Eng Team', 'Engineering'),
      [REMOVE_PATH]: ok({ success: true }),
    });
    render(withControlPlane(<GroupDetailClient />));

    await screen.findByText('Eng Team');
    type('Member user ID', 'u-7');
    await click('Remove member');

    await waitFor(() =>
      expect(sent.some((r) => r.method === 'DELETE' && r.path === '/api/v1/iam/tenants/t-1/groups/g-1/members/u-7')).toBe(
        true
      )
    );
    await waitFor(() => expect(toasts('Member removed').length).toBeGreaterThan(0));
  });

  it("shows a refused add with the server's message as a destructive toast", async () => {
    stubControlPlane({
      [GET_PATH]: storedGroup('Eng Team', 'Engineering'),
      [ADD_PATH]: refused(404, 'user u-7 not found'),
    });
    render(withControlPlane(<GroupDetailClient />));

    await screen.findByText('Eng Team');
    type('Member user ID', 'u-7');
    await click('Add member');

    const toast = await screen.findByText('Failed to add member: user u-7 not found');
    expect(toast.getAttribute('data-variant')).toBe('destructive');
  });

  it('sends nothing for an empty user ID', async () => {
    const sent = stubControlPlane({ [GET_PATH]: storedGroup('Eng Team', 'Engineering') });
    render(withControlPlane(<GroupDetailClient />));

    await screen.findByText('Eng Team');
    type('Member user ID', '   ');
    expect((screen.getByRole('button', { name: 'Add member' }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole('button', { name: 'Remove member' }) as HTMLButtonElement).disabled).toBe(true);
    await click('Add member');
    await click('Remove member');
    expect(sent.some((r) => r.method === 'POST' || r.method === 'DELETE')).toBe(false);
  });
});
