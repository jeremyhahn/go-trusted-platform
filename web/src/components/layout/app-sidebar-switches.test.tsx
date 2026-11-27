import { cleanup, render, screen } from '@testing-library/react';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';

import { AuthProvider } from '@/contexts/AuthContext';
import { SidebarProvider } from '@/components/ui/sidebar';
import { AppSidebar } from './app-sidebar';

// #2066: the sidebar's Networking group links the switches page.

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  usePathname: () => '/networking/switches',
}));

const originalMatches = Element.prototype.matches;

beforeAll(() => {
  // jsdom spends seconds resolving ':modal'; nothing in the sidebar is modal.
  Element.prototype.matches = function matches(this: Element, selectors: string): boolean {
    if (selectors.includes(':modal')) return false;
    return originalMatches.call(this, selectors);
  };
});

afterAll(() => {
  Element.prototype.matches = originalMatches;
});

afterEach(() => {
  cleanup();
});

describe('AppSidebar', () => {
  it('links the switches page under Networking', () => {
    render(
      <AuthProvider>
        <SidebarProvider>
          <AppSidebar />
        </SidebarProvider>
      </AuthProvider>,
    );
    expect(screen.getByRole('link', { name: 'Switches' }).getAttribute('href')).toBe('/networking/switches');
  });
});
