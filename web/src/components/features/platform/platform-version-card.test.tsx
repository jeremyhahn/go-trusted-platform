import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { PlatformVersionCard } from './platform-version-card';

// #2047: the System Health page's Platform version card shows the build the
// control plane reports on GET /api/v1/platform/version.

const VERSION_PATH = 'GET /api/v1/platform/version';

describe('PlatformVersionCard', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('shows the version and git commit the server reports', async () => {
    stubControlPlane({
      [VERSION_PATH]: ok({
        version: '1.4.2',
        build_time: '2026-11-20T00:00:00Z',
        git_commit: 'abc1234',
        go_version: 'go1.25.4',
      }),
    });
    render(withControlPlane(<PlatformVersionCard />));

    expect(await screen.findByText('1.4.2')).toBeDefined();
    expect(screen.getByText('abc1234')).toBeDefined();
    expect(screen.getByText('go1.25.4')).toBeDefined();
  });

  it('shows a refusal inline', async () => {
    stubControlPlane({ [VERSION_PATH]: refused(404, 'not found') });
    render(withControlPlane(<PlatformVersionCard />));

    expect((await screen.findByRole('alert')).textContent).toContain('HTTP 404: not found');
  });
});
