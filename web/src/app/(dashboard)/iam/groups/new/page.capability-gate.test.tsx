// #2033 item 5: Create Group is wrapped in the capability gate on the tenant group create op.
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import NewGroupPage from './page';

const router = { push: vi.fn(), back: vi.fn() };
vi.mock('next/navigation', () => ({
  usePathname: () => '/iam/groups/new',
  useRouter: () => router,
}));

const authResult = { tenantId: 't-1', isLoading: false };
vi.mock('@/contexts/AuthContext', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/contexts/AuthContext')>()),
  useAuth: () => authResult,
}));

const toast = vi.fn();
const iam = { createGroup: vi.fn() };
const mutate = vi.fn();
vi.mock('@/hooks', () => ({
  useIAM: () => iam,
  useToast: () => ({ toast }),
  useMutation: () => ({ mutate, isLoading: false }),
}));

const caps = vi.hoisted(() => ({ capability: vi.fn() }));
vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({
    loading: false,
    error: undefined,
    capability: caps.capability,
  }),
}));

const createOp = 'POST /api/v1/iam/tenants/{tenant}/groups';

function typeName(value: string) {
  fireEvent.change(screen.getByLabelText('Name *'), { target: { value } });
}

function createButton() {
  return screen.getByRole('button', { name: 'Create Group' }) as HTMLButtonElement;
}

describe('NewGroupPage capability gate', () => {
  beforeEach(() => {
    caps.capability.mockReset();
    caps.capability.mockImplementation(() => ({ enabled: true }));
    mutate.mockReset();
    iam.createGroup.mockReset();
    router.push.mockReset();
  });

  afterEach(() => cleanup());

  it("withholds Create Group with the server's reason when the tenant group create is not offered", () => {
    caps.capability.mockImplementation((op: string) =>
      op === createOp ? { enabled: false, reason: 'not-configured: iam' } : { enabled: true },
    );
    render(<NewGroupPage />);
    typeName('engineering');

    const button = createButton();
    expect(button.disabled).toBe(true);
    expect(button.getAttribute('title')).toBe('not-configured: iam');
    expect(button.getAttribute('data-capability-op')).toBe(createOp);
    expect(button.getAttribute('data-capability-enabled')).toBe('false');

    fireEvent.click(createButton());
    expect(mutate).not.toHaveBeenCalled();
    expect(iam.createGroup).not.toHaveBeenCalled();

    const cancel = screen.getByRole('button', { name: 'Cancel' }) as HTMLButtonElement;
    expect(cancel.disabled).toBe(false);
  });

  it('asks the gate for the tenant group create op and keeps the name rule when it is offered', () => {
    render(<NewGroupPage />);

    expect(caps.capability).toHaveBeenCalledWith(createOp);
    expect(createButton().getAttribute('data-capability-enabled')).toBe('true');
    expect(createButton().disabled).toBe(true);

    typeName('engineering');
    expect(createButton().disabled).toBe(false);
    expect(createButton().hasAttribute('title')).toBe(false);

    fireEvent.click(createButton());
    expect(mutate).toHaveBeenCalledTimes(1);
  });
});
