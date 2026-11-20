import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const { vtpm, toast } = vi.hoisted(() => ({
  vtpm: {
    listTemplates: vi.fn(),
    listBundles: vi.fn(),
    createTemplate: vi.fn(),
    getTemplate: vi.fn(),
    cloneTemplate: vi.fn(),
    deleteTemplate: vi.fn(),
    importBundle: vi.fn(),
    getBundle: vi.fn(),
    validateBundle: vi.fn(),
    getBundlePath: vi.fn(),
    getTPMSocketPath: vi.fn(),
    getNVRAMPath: vi.fn(),
  },
  toast: vi.fn(),
}));

// Only the vTPM service and the toast are replaced; useApi and useMutation
// are the real SDK hooks, so the tests cover how the hook drives them.
vi.mock('@/hooks', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/hooks')>()),
  useVTPM: () => vtpm,
}));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast }) }));

import { useVTPMTemplates, VTPM_BUNDLE_PAGE_SIZE } from './use-vtpm-templates';

const template = {
  id: 'tmpl-a',
  description: 'base',
  tpm_state_dir: '/var/lib/vtpm/templates/tmpl-a/tpm',
  nvram_path: '/var/lib/vtpm/templates/tmpl-a/OVMF_VARS.fd',
  ek_algorithm: 'RSA',
  secure_boot_enabled: true,
};
const bundle = { id: 'bndl-1', mode: 'clone', cloned_from: 'tmpl-a' };

function ok<T>(data: T) {
  return Promise.resolve({ data });
}

beforeEach(() => {
  for (const fn of Object.values(vtpm)) fn.mockReset();
  toast.mockReset();
  vtpm.listTemplates.mockImplementation(() => ok({ templates: [template] }));
  vtpm.listBundles.mockImplementation(() => ok({ bundles: [bundle], total: 1 }));
});

afterEach(() => cleanup());

async function render() {
  const view = renderHook(() => useVTPMTemplates());
  await waitFor(() => {
    expect(view.result.current.templatesLoading).toBe(false);
    expect(view.result.current.bundlesLoading).toBe(false);
  });
  return view;
}

describe('useVTPMTemplates lists', () => {
  it('loads templates and the first bundle page from the service', async () => {
    const { result } = await render();
    expect(vtpm.listTemplates).toHaveBeenCalledTimes(1);
    expect(vtpm.listBundles).toHaveBeenCalledWith({
      options: { limit: VTPM_BUNDLE_PAGE_SIZE, offset: 0 },
    });
    expect(result.current.templates).toEqual([template]);
    expect(result.current.bundles).toEqual([bundle]);
    expect(result.current.hasNextBundlePage).toBe(false);
  });

  it('pages bundles by limit and offset', async () => {
    const full = Array.from({ length: VTPM_BUNDLE_PAGE_SIZE }, (_, i) => ({
      id: `b-${i}`,
      mode: 'import',
    }));
    vtpm.listBundles.mockImplementation(() => ok({ bundles: full }));
    const { result } = await render();
    expect(result.current.hasNextBundlePage).toBe(true);

    act(() => result.current.nextBundlePage());
    await waitFor(() =>
      expect(vtpm.listBundles).toHaveBeenLastCalledWith({
        options: { limit: VTPM_BUNDLE_PAGE_SIZE, offset: VTPM_BUNDLE_PAGE_SIZE },
      })
    );
    expect(result.current.bundleOffset).toBe(VTPM_BUNDLE_PAGE_SIZE);

    act(() => result.current.prevBundlePage());
    act(() => result.current.prevBundlePage());
    await waitFor(() => expect(result.current.bundleOffset).toBe(0));
  });
});

describe('useVTPMTemplates template writes', () => {
  it('creates a template with the form values and refetches the list', async () => {
    vtpm.createTemplate.mockImplementation(() => ok(template));
    const { result } = await render();
    await act(async () => {
      await result.current.createTemplate.mutateAsync({
        id: 'tmpl-a',
        description: 'base',
        ekAlgorithm: 'ECC',
        secureBootEnabled: false,
      });
    });
    expect(vtpm.createTemplate).toHaveBeenCalledWith({
      options: {
        id: 'tmpl-a',
        description: 'base',
        ekAlgorithm: 'ECC',
        secureBootEnabled: false,
      },
    });
    await waitFor(() => expect(vtpm.listTemplates).toHaveBeenCalledTimes(2));
  });

  it('gets a template by id', async () => {
    vtpm.getTemplate.mockImplementation(() => ok(template));
    const { result } = await render();
    let got: unknown;
    await act(async () => {
      got = await result.current.getTemplate.mutateAsync('tmpl-a');
    });
    expect(vtpm.getTemplate).toHaveBeenCalledWith('tmpl-a');
    expect(got).toEqual(template);
  });

  it('clones a template into a bundle and refetches bundles', async () => {
    vtpm.cloneTemplate.mockImplementation(() => ok(bundle));
    const { result } = await render();
    await act(async () => {
      await result.current.cloneTemplate.mutateAsync({ templateId: 'tmpl-a', hostname: 'vm-1' });
    });
    expect(vtpm.cloneTemplate).toHaveBeenCalledWith({
      options: { templateId: 'tmpl-a', hostname: 'vm-1' },
    });
    await waitFor(() => expect(vtpm.listBundles).toHaveBeenCalledTimes(2));
    expect(vtpm.listTemplates).toHaveBeenCalledTimes(1);
  });

  it('deletes a template and refetches the list', async () => {
    vtpm.deleteTemplate.mockImplementation(() => ok({ success: true }));
    const { result } = await render();
    await act(async () => {
      await result.current.deleteTemplate.mutateAsync('tmpl-a');
    });
    expect(vtpm.deleteTemplate).toHaveBeenCalledWith('tmpl-a');
    await waitFor(() => expect(vtpm.listTemplates).toHaveBeenCalledTimes(2));
  });
});

describe('useVTPMTemplates bundle operations', () => {
  it('imports an archive and refetches bundles', async () => {
    vtpm.importBundle.mockImplementation(() => ok(bundle));
    const archive = new Blob(['tar'], { type: 'application/gzip' });
    const { result } = await render();
    await act(async () => {
      await result.current.importBundle.mutateAsync(archive);
    });
    expect(vtpm.importBundle).toHaveBeenCalledWith(archive);
    await waitFor(() => expect(vtpm.listBundles).toHaveBeenCalledTimes(2));
  });

  it.each([
    ['getBundle', bundle],
    ['validateBundle', { valid: false, errors: ['manifest missing'] }],
    ['getBundlePath', { path: '/var/lib/vtpm/bundles/bndl-1' }],
    ['getTPMSocketPath', { path: '/run/vtpm/bndl-1/swtpm-sock' }],
    ['getNVRAMPath', { path: '/var/lib/vtpm/bundles/bndl-1/OVMF_VARS.fd' }],
  ] as const)('%s calls the service with the bundle id', async (method, data) => {
    vtpm[method].mockImplementation(() => ok(data));
    const { result } = await render();
    let got: unknown;
    await act(async () => {
      got = await result.current[method].mutateAsync('bndl-1');
    });
    expect(vtpm[method]).toHaveBeenCalledWith('bndl-1');
    expect(got).toEqual(data);
  });
});

describe('useVTPMTemplates errors', () => {
  it('toasts the server error of a failed write and does not refetch', async () => {
    vtpm.createTemplate.mockImplementation(() =>
      Promise.resolve({ error: { code: 'CONFLICT', message: 'template exists' } })
    );
    const { result } = await render();
    await act(async () => {
      await result.current.createTemplate
        .mutateAsync({ id: 'tmpl-a', ekAlgorithm: 'RSA', secureBootEnabled: true })
        .catch(() => undefined);
    });
    expect(toast).toHaveBeenCalledWith(
      expect.objectContaining({ description: 'template exists', variant: 'destructive' })
    );
    expect(vtpm.listTemplates).toHaveBeenCalledTimes(1);
  });

  it('toasts a failed template listing', async () => {
    vtpm.listTemplates.mockImplementation(() => Promise.reject(new Error('backend down')));
    await render();
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({ description: 'backend down', variant: 'destructive' })
      )
    );
  });
});
