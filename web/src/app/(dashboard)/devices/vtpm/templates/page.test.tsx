import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// #2071: every control on the templates page is wrapped in the capability
// gate with its server op. These tests stub the capabilities hook (the
// server's answer) and the templates hook (the SDK boundary).

const caps = vi.hoisted(() => ({
  off: new Set<string>(),
  reason: 'not offered by this server',
}));

vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({
    capability: (op: string) =>
      caps.off.has(op) ? { enabled: false, reason: caps.reason } : { enabled: true },
  }),
}));

const mutation = () => ({ mutateAsync: vi.fn(), isLoading: false });

const vt = vi.hoisted(() => ({ current: {} as Record<string, unknown> }));

vi.mock('@/hooks/use-vtpm-templates', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/hooks/use-vtpm-templates')>()),
  useVTPMTemplates: () => vt.current,
}));

import VTPMTemplatesPage from './page';

const OPS = {
  create: 'POST /api/v1/vtpm/templates',
  details: 'GET /api/v1/vtpm/templates/{id}',
  clone: 'POST /api/v1/vtpm/templates/{id}/clone',
  delete: 'DELETE /api/v1/vtpm/templates/{id}',
};

function button(name: string) {
  return screen.getByRole('button', { name }) as HTMLButtonElement;
}

describe('VTPMTemplatesPage capability gate', () => {
  beforeEach(() => {
    caps.off.clear();
    vt.current = {
      templates: [{ id: 'golden', ek_algorithm: 'RSA', secure_boot_enabled: false }],
      templatesLoading: false,
      createTemplate: mutation(),
      getTemplate: mutation(),
      cloneTemplate: mutation(),
      deleteTemplate: mutation(),
    };
  });

  afterEach(() => {
    cleanup();
  });

  it('each template control carries its server op', () => {
    render(<VTPMTemplatesPage />);

    const controls: [string, string][] = [
      ['New template', OPS.create],
      ['Details', OPS.details],
      ['Clone', OPS.clone],
      ['Delete', OPS.delete],
    ];
    for (const [name, op] of controls) {
      const b = button(name);
      expect(b.getAttribute('data-capability-op')).toBe(op);
      expect(b.getAttribute('data-capability-enabled')).toBe('true');
      expect(b.disabled).toBe(false);
    }
  });

  it('a control whose op the server does not offer is disabled with the reason', () => {
    caps.off.add(OPS.clone);
    caps.off.add(OPS.delete);
    render(<VTPMTemplatesPage />);

    for (const name of ['Clone', 'Delete']) {
      const b = button(name);
      expect(b.disabled).toBe(true);
      expect(b.getAttribute('title')).toBe(caps.reason);
      expect(b.getAttribute('data-capability-enabled')).toBe('false');
    }
    for (const name of ['New template', 'Details']) {
      const b = button(name);
      expect(b.disabled).toBe(false);
      expect(b.getAttribute('data-capability-enabled')).toBe('true');
    }
  });
});
