import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, stubControlPlane, withControlPlane, type Answer, type SentRequest } from '@/test/control-plane-fetch';
import { ConfigSectionEditor } from './config-section-editor';

// #2047: the config page applies one key of a section through UpdateConfig
// (PUT /api/v1/platform/config/sections/{section}), only when the server
// enables it.

const UPDATE_OP = 'PUT /api/v1/platform/config/sections/{section}';

function caps(off = false): Answer {
  const capabilities = [
    off
      ? { op: UPDATE_OP, kind: 'route', enabled: false, reason: 'not-configured: config' }
      : { op: UPDATE_OP, kind: 'route', enabled: true },
  ];
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

function puts(sent: SentRequest[]): SentRequest[] {
  return sent.filter((r) => r.method === 'PUT');
}

function type(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

describe('ConfigSectionEditor', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('applies one key through UpdateConfig', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/capabilities': caps(),
      'PUT /api/v1/platform/config/sections/logging': ok({ section: 'logging', persisted: false, message: 'applied' }),
    });
    const onApplied = vi.fn();
    render(withControlPlane(<ConfigSectionEditor onApplied={onApplied} />));

    const apply = await screen.findByRole('button', { name: 'Apply' });
    await waitFor(() => expect(apply.getAttribute('data-capability-enabled')).toBe('true'));
    type('Section', 'logging');
    type('Key', 'level');
    type('Value', 'debug');
    await act(async () => {
      fireEvent.click(apply);
    });

    await waitFor(() => expect(onApplied).toHaveBeenCalledTimes(1));
    const sentPuts = puts(sent);
    expect(sentPuts).toHaveLength(1);
    expect(sentPuts[0].path).toBe('/api/v1/platform/config/sections/logging');
    expect(sentPuts[0].body).toEqual({ values: { level: 'debug' }, persist: false });
  });

  it('Apply is disabled when the server does not enable it', async () => {
    stubControlPlane({ 'GET /api/v1/capabilities': caps(true) });
    render(withControlPlane(<ConfigSectionEditor />));

    const apply = await screen.findByRole('button', { name: 'Apply' });
    await waitFor(() => expect(apply.getAttribute('data-capability-enabled')).toBe('false'));
    expect((apply as HTMLButtonElement).disabled).toBe(true);
  });
});
