import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';

import type { SystemStatus } from '@/types/platform';
import { HealthStatus } from './health-status';

describe('HealthStatus', () => {
  afterEach(cleanup);

  it.each([
    ['healthy', 'Healthy', 'bg-green-100', 'text-green-600'],
    ['degraded', 'Degraded', 'bg-yellow-100', 'text-yellow-600'],
    ['down', 'Down', 'bg-red-100', 'text-red-600'],
  ] as const)('renders %s as %s with its colours', (status, label, bg, text) => {
    const { container } = render(<HealthStatus status={status} />);
    const labelEl = screen.getByText(label);
    expect(labelEl.className).toContain(text);
    const root = container.firstElementChild as HTMLElement;
    expect(root.className).toContain(bg);
    expect(root.querySelector('svg')).not.toBeNull();
  });

  it('appends a custom className to the root', () => {
    const { container } = render(<HealthStatus status="healthy" className="extra-class" />);
    const root = container.firstElementChild as HTMLElement;
    expect(root.className).toContain('extra-class');
    expect(root.className).toContain('inline-flex');
  });

  it('defaults className to empty without an "undefined" class', () => {
    const { container } = render(<HealthStatus status="down" />);
    const root = container.firstElementChild as HTMLElement;
    expect(root.className).not.toContain('undefined');
  });

  it('renders an unknown status from the server as Unknown instead of crashing', () => {
    render(<HealthStatus status={'maintenance' as SystemStatus} />);
    expect(screen.getByText('Unknown')).toBeDefined();
  });
});
