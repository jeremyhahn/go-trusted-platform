import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('./device-detail-client', () => ({
  default: () => <div data-testid="device-detail-client" />,
}));

import Page, { generateStaticParams } from './page';

afterEach(() => {
  cleanup();
});

describe('devices/[id] route', () => {
  it('generateStaticParams returns exactly one placeholder id', () => {
    const params = generateStaticParams();
    expect(params).toEqual([{ id: '__placeholder__' }]);
  });

  it('generateStaticParams returns a fresh array on each call', () => {
    const a = generateStaticParams();
    const b = generateStaticParams();
    expect(a).not.toBe(b);
    a.push({ id: 'mutated' });
    expect(generateStaticParams()).toHaveLength(1);
  });

  it('Page renders the device detail client component', () => {
    render(<Page />);
    expect(screen.getByTestId('device-detail-client')).toBeTruthy();
  });

  it('Page renders the client component exactly once', () => {
    render(<Page />);
    expect(screen.getAllByTestId('device-detail-client')).toHaveLength(1);
  });
});
