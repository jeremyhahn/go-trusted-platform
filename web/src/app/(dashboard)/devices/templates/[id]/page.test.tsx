import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';

vi.mock('./template-detail-client', () => ({
  default: () => <div data-testid="template-detail-client">template detail</div>,
}));

import Page, { generateStaticParams } from './page';

describe('devices/templates/[id] page', () => {
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
    it('renders the template detail client component', () => {
      render(<Page />);
      expect(screen.getByTestId('template-detail-client').textContent).toBe('template detail');
    });

    it('renders only the client component', () => {
      const { container } = render(<Page />);
      expect(container.children).toHaveLength(1);
    });
  });
});
