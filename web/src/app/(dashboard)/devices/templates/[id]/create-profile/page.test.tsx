import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('./create-profile-client', () => ({
  default: () => <div data-testid="create-profile-client" />,
}));

import Page, { generateStaticParams } from './page';

afterEach(() => {
  cleanup();
});

describe('devices/templates/[id]/create-profile route', () => {
  it('generateStaticParams returns exactly one placeholder id', () => {
    expect(generateStaticParams()).toEqual([{ id: '__placeholder__' }]);
  });

  it('generateStaticParams returns a fresh array on each call', () => {
    const a = generateStaticParams();
    a.push({ id: 'mutated' });
    expect(generateStaticParams()).toEqual([{ id: '__placeholder__' }]);
  });

  it('Page renders the create-profile client component exactly once', () => {
    render(<Page />);
    expect(screen.getAllByTestId('create-profile-client')).toHaveLength(1);
  });
});
