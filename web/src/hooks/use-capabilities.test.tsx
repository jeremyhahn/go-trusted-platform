import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { CAPABILITIES_LOADING_REASON, useCapabilities } from './use-capabilities';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const OP = 'DELETE /api/v1/proxy/pools/{id}';

function Probe({ seen }: { seen: string[] }) {
  const { capability } = useCapabilities();
  const answer = capability(OP);
  seen.push(answer.enabled ? 'enabled' : (answer.reason ?? 'disabled'));
  return <span data-testid="probe">{answer.enabled ? 'enabled' : answer.reason}</span>;
}

// A table row's Gated control mounts only after the page's own read settled.
function Host({ seen }: { seen: string[] }) {
  const { loading } = useCapabilities();
  return loading ? null : <Probe seen={seen} />;
}

describe('useCapabilities', () => {
  it('answers a control that mounts after the read settled from its first render', async () => {
    stubControlPlane({
      'GET /api/v1/capabilities': ok({ capabilities: [{ op: OP, kind: 'route', enabled: true }], total: 1, enabled: 1 }),
    });
    const seen: string[] = [];
    render(withControlPlane(<Host seen={seen} />));

    expect((await screen.findByTestId('probe')).textContent).toBe('enabled');
    expect(seen).not.toContain(CAPABILITIES_LOADING_REASON);
    expect(seen[0]).toBe('enabled');
  });
});
