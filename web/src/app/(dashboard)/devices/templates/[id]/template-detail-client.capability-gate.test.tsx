// #2033: the device template detail page reads the capability gate. The
// template is not fetched when its GET op is off (a not-enabled card shows the
// reason); Edit Template follows PUT, Create Profile from Template follows the
// create-profile POST, and Delete with the dialog's Delete Template follow DELETE.
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import TemplateDetailClient from './template-detail-client';

const router = vi.hoisted(() => ({ push: vi.fn(), back: vi.fn() }));
vi.mock('next/navigation', () => ({
  useParams: () => ({ id: '42' }),
  usePathname: () => '/devices/templates/42',
  useRouter: () => router,
}));

const caps = vi.hoisted(() => ({ capability: vi.fn() }));
vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({
    loading: false,
    error: undefined,
    capability: caps.capability,
  }),
}));

const h = vi.hoisted(() => ({
  toast: vi.fn(),
  device: { getTemplate: vi.fn(), deleteTemplate: vi.fn() },
}));
vi.mock('@/hooks', () => ({
  useDevice: () => h.device,
  useToast: () => ({ toast: h.toast }),
  useApi: (fetcher: () => unknown, _deps: unknown[], opts?: { enabled?: boolean }) => {
    if (opts?.enabled !== false) {
      fetcher();
    }
    return {
      data: {
        id: '42',
        tenant_id: 't-1',
        name: 'edge-gw',
        description: '',
        role: 'gateway',
        match_rules: {},
        config: {},
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z',
      },
      loading: false,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    };
  },
  useMutation: (
    fn: (v: unknown) => unknown,
    opts?: { onSuccess?: (r: unknown) => void; onError?: (e: unknown) => void },
  ) => ({
    mutate: (v: unknown) => Promise.resolve(fn(v)).then(opts?.onSuccess, opts?.onError),
    isLoading: false,
  }),
}));

const getOp = 'GET /api/v1/device/templates/{id:[0-9]+}';
const updateOp = 'PUT /api/v1/device/templates/{id:[0-9]+}';
const createProfileOp = 'POST /api/v1/device/templates/{id:[0-9]+}/create-profile';
const deleteOp = 'DELETE /api/v1/device/templates/{id:[0-9]+}';
const reason = 'not-configured: device';

function offOnly(off: string) {
  caps.capability.mockImplementation((op: string) =>
    op === off ? { enabled: false, reason } : { enabled: true },
  );
}

function button(name: string) {
  return screen.getByRole('button', { name }) as HTMLButtonElement;
}

function expectWithheld(el: HTMLButtonElement, op: string) {
  expect(el.disabled).toBe(true);
  expect(el.title).toBe(reason);
  expect(el.getAttribute('data-capability-op')).toBe(op);
  expect(el.getAttribute('data-capability-enabled')).toBe('false');
}

describe('TemplateDetailClient capability gate', () => {
  beforeEach(() => {
    caps.capability.mockReset();
    caps.capability.mockImplementation(() => ({ enabled: true }));
    h.device.getTemplate.mockReset();
    h.device.deleteTemplate.mockReset();
    h.device.getTemplate.mockResolvedValue({});
    h.device.deleteTemplate.mockResolvedValue({});
    router.push.mockReset();
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it('does not fetch the template and shows the reason when the get op is off', () => {
    offOnly(getOp);
    render(<TemplateDetailClient />);

    expect(h.device.getTemplate).not.toHaveBeenCalled();
    expect(screen.getByTestId('template-not-enabled').textContent).toContain(reason);
    expect(screen.queryByText('Loading template...')).toBeNull();
  });

  it('withholds Edit Template with the server reason when the update op is off', () => {
    offOnly(updateOp);
    render(<TemplateDetailClient />);

    const edit = button('Edit Template');
    expectWithheld(edit, updateOp);
    fireEvent.click(edit);
    expect(router.push).not.toHaveBeenCalled();
  });

  it('withholds Create Profile from Template when the create-profile op is off', () => {
    offOnly(createProfileOp);
    render(<TemplateDetailClient />);

    const create = button('Create Profile from Template');
    expectWithheld(create, createProfileOp);
    fireEvent.click(create);
    expect(router.push).not.toHaveBeenCalled();
  });

  it('withholds Delete with the server reason when the delete op is off', () => {
    offOnly(deleteOp);
    render(<TemplateDetailClient />);

    const del = button('Delete template');
    expectWithheld(del, deleteOp);
    fireEvent.click(del);
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('offers every control when the server does', async () => {
    render(<TemplateDetailClient />);

    expect(h.device.getTemplate).toHaveBeenCalled();
    for (const name of ['Edit Template', 'Create Profile from Template', 'Delete template']) {
      const el = button(name);
      expect(el.disabled).toBe(false);
      expect(el.getAttribute('data-capability-enabled')).toBe('true');
    }

    fireEvent.click(button('Delete template'));
    const confirm = await screen.findByRole('button', { name: 'Delete Template' });
    expect((confirm as HTMLButtonElement).disabled).toBe(false);
    expect(confirm.getAttribute('data-capability-op')).toBe(deleteOp);
    fireEvent.click(confirm);
    expect(h.device.deleteTemplate).toHaveBeenCalledTimes(1);
  });
});
