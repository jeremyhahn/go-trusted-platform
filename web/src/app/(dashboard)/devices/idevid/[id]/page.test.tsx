import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('./idevid-detail-client', () => ({
  default: () => <div data-testid="idevid-detail-client" />,
}));

import Page, { generateStaticParams } from './page';

afterEach(() => {
  cleanup();
});

describe('devices/idevid/[id] route', () => {
  it('generateStaticParams returns exactly one placeholder id', () => {
    expect(generateStaticParams()).toEqual([{ id: '__placeholder__' }]);
  });

  it('generateStaticParams returns a fresh array on each call', () => {
    const a = generateStaticParams();
    a.push({ id: 'mutated' });
    expect(generateStaticParams()).toEqual([{ id: '__placeholder__' }]);
  });

  it('Page renders the IDevID detail client component exactly once', () => {
    render(<Page />);
    expect(screen.getAllByTestId('idevid-detail-client')).toHaveLength(1);
  });
});
