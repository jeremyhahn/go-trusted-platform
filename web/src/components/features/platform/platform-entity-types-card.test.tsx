import { cleanup, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import { PlatformEntityTypesCard } from './platform-entity-types-card';

// #2047: the System Health page reaches ListEntityTypes
// (GET /api/v1/platform/entity-types) through the real SDK client.

describe('PlatformEntityTypesCard', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('lists the entity types with their counts', async () => {
    stubControlPlane({
      'GET /api/v1/platform/entity-types': ok({
        entityTypes: [
          { name: 'users', entityCount: 3, status: 'active' },
          { name: 'groups', entityCount: 0, status: 'empty' },
        ],
        totalEntities: 3,
        activeTypes: 1,
      }),
    });
    render(withControlPlane(<PlatformEntityTypesCard />));

    const users = await screen.findByTestId('entity-type-users');
    expect(within(users).getByText('users')).toBeTruthy();
    expect(within(users).getByText('3')).toBeTruthy();
    const groups = screen.getByTestId('entity-type-groups');
    expect(within(groups).getByText('groups')).toBeTruthy();
    expect(within(groups).getByText('0')).toBeTruthy();
    expect(screen.getByTestId('entity-types-total').textContent).toContain('3');
  });

  it('shows the refusal', async () => {
    stubControlPlane({
      'GET /api/v1/platform/entity-types': refused(503, 'registry offline'),
    });
    render(withControlPlane(<PlatformEntityTypesCard />));

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('HTTP 503: registry offline');
  });
});
