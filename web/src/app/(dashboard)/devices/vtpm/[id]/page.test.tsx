import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';

vi.mock('./vtpm-detail-client', () => ({
  default: () => <div data-testid="vtpm-detail-client">vtpm detail</div>,
}));

import Page, { generateStaticParams } from './page';

afterEach(() => cleanup());

describe('devices/vtpm/[id] page', () => {
  describe('generateStaticParams', () => {
    it('returns exactly one placeholder id for the static export', () => {
      expect(generateStaticParams()).toEqual([{ id: '__placeholder__' }]);
    });

    it('returns a fresh array on each call', () => {
      const a = generateStaticParams();
      const b = generateStaticParams();
      expect(a).not.toBe(b);
      expect(a).toEqual(b);
    });
  });

  describe('Page', () => {
    it('renders the vTPM detail client component', () => {
      render(<Page />);
      expect(screen.getByTestId('vtpm-detail-client').textContent).toBe('vtpm detail');
    });

    it('renders only the client component', () => {
      const { container } = render(<Page />);
      expect(container.children).toHaveLength(1);
    });
  });
});
