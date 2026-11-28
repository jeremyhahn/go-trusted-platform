import type { ComponentProps, ReactNode } from 'react';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { DeviceTemplate } from 'trusted-platform-sdk';

const { off, push, templatesHook, toast } = vi.hoisted(() => ({
  off: new Set<string>(),
  push: vi.fn(),
  toast: vi.fn(),
  templatesHook: {
    templates: [] as unknown[],
    isLoading: false,
    error: null,
    refetch: vi.fn(),
    create: { mutateAsync: vi.fn(), isLoading: false },
    remove: { mutateAsync: vi.fn(), isLoading: false },
  },
}));

vi.mock('@/hooks', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/hooks')>()),
  useDeviceTemplates: () => templatesHook,
  useToast: () => ({ toast }),
}));

vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({
    loading: false,
    error: undefined,
    capability: (op: string) =>
      off.has(op) ? { enabled: false, reason: 'not-configured: device' } : { enabled: true },
  }),
}));

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push }),
}));

// Passthrough menu so the items render without opening Radix.
vi.mock('@/components/ui/dropdown-menu', () => ({
  DropdownMenu: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  DropdownMenuTrigger: ({ children }: { children: ReactNode }) => <>{children}</>,
  DropdownMenuContent: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  DropdownMenuLabel: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  DropdownMenuSeparator: () => <hr />,
  DropdownMenuItem: (props: ComponentProps<'button'>) => (
    <button type="button" role="menuitem" {...props} />
  ),
}));

import DeviceTemplatesPage from './page';

const CREATE_OP = 'POST /api/v1/device/templates';
const UPDATE_OP = 'PUT /api/v1/device/templates/{id:[0-9]+}';
const DELETE_OP = 'DELETE /api/v1/device/templates/{id:[0-9]+}';

const workers = {
  id: '7101',
  name: 'workers',
  description: 'd',
  role: 'worker',
  created_at: '2026-11-01T00:00:00Z',
  updated_at: '2026-11-01T00:00:00Z',
} as unknown as DeviceTemplate;

const item = (name: string) => screen.getByRole('menuitem', { name }) as HTMLButtonElement;
const createButton = () =>
  screen.getByRole('button', { name: 'Create Template' }) as HTMLButtonElement;

function expectGatedOff(el: HTMLButtonElement, op: string) {
  expect(el.getAttribute('data-capability-op')).toBe(op);
  expect(el.getAttribute('data-capability-enabled')).toBe('false');
  expect(el.disabled).toBe(true);
  expect(el.getAttribute('title')).toBe('not-configured: device');
}

beforeEach(() => {
  templatesHook.templates = [workers];
  push.mockReset();
  templatesHook.create.mutateAsync.mockReset();
  templatesHook.remove.mutateAsync.mockReset();
});

afterEach(() => {
  cleanup();
  off.clear();
});

describe('DeviceTemplatesPage capability gate', () => {
  it('withholds Create Template and Duplicate when the create is not offered', () => {
    off.add(CREATE_OP);
    render(<DeviceTemplatesPage />);

    expectGatedOff(createButton(), CREATE_OP);
    const duplicate = item('Duplicate');
    expectGatedOff(duplicate, CREATE_OP);
    fireEvent.click(duplicate);
    expect(templatesHook.create.mutateAsync).not.toHaveBeenCalled();
  });

  it('withholds Edit Template when the update is not offered', () => {
    off.add(UPDATE_OP);
    render(<DeviceTemplatesPage />);

    const edit = item('Edit Template');
    expectGatedOff(edit, UPDATE_OP);
    fireEvent.click(edit);
    expect(push).not.toHaveBeenCalled();
  });

  it('withholds Delete when the delete is not offered', () => {
    off.add(DELETE_OP);
    render(<DeviceTemplatesPage />);

    const del = item('Delete');
    expectGatedOff(del, DELETE_OP);
    fireEvent.click(del);
    expect(templatesHook.remove.mutateAsync).not.toHaveBeenCalled();
  });

  it('offers every write when the server offers it, and Edit opens the detail page', () => {
    render(<DeviceTemplatesPage />);

    expect(createButton().getAttribute('data-capability-enabled')).toBe('true');
    expect(item('Duplicate').getAttribute('data-capability-enabled')).toBe('true');
    expect(item('Delete').getAttribute('data-capability-enabled')).toBe('true');
    const edit = item('Edit Template');
    expect(edit.getAttribute('data-capability-enabled')).toBe('true');
    fireEvent.click(edit);
    expect(push).toHaveBeenCalledWith('/devices/templates/7101');
  });
});
