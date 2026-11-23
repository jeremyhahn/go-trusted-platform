import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { useState } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { CAPABILITIES_LOADING_REASON, useCapabilities } from './use-capabilities';

const OP = 'POST /api/v1/proxy/pools';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

// Every render of a probe records what its capability answered.
const renders: Record<string, Array<string>> = {};

function Probe({ name }: { name: string }) {
  const answer = useCapabilities().capability(OP);
  const seen = answer.enabled ? 'enabled' : (answer.reason ?? 'disabled');
  (renders[name] ??= []).push(seen);
  return <span data-testid={name}>{seen}</span>;
}

function Host() {
  const [late, setLate] = useState(false);
  return (
    <>
      <Probe name="early" />
      <button type="button" onClick={() => setLate(true)}>
        mount
      </button>
      {late ? <Probe name="late" /> : null}
    </>
  );
}

describe('useCapabilities', () => {
  it('answers a control mounted after the read resolved on its first render', async () => {
    stubControlPlane({
      'GET /api/v1/capabilities': ok({
        capabilities: [{ op: OP, kind: 'route', enabled: true }],
        total: 1,
        enabled: 1,
      }),
    });
    render(withControlPlane(<Host />));

    expect(renders.early?.[0]).toBe(CAPABILITIES_LOADING_REASON);
    await waitFor(() => expect(screen.getByTestId('early').textContent).toBe('enabled'));

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'mount' }));
    });

    expect(renders.late?.[0]).toBe('enabled');
    expect(renders.late?.every((seen) => seen === 'enabled')).toBe(true);
  });
});
