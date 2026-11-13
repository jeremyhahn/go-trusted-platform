import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';

import type { ResourceUsage as ResourceUsageType } from '@/types/platform';
import { ResourceUsage } from './resource-usage';

const resources: ResourceUsageType = {
  cpu: { used: 2.4, total: 8 },
  memory: { usedMB: 4096, totalMB: 16384 },
  disk: { usedGB: 120, totalGB: 500 },
};

function bars(container: HTMLElement): HTMLElement[] {
  return Array.from(container.querySelectorAll<HTMLElement>('div.absolute'));
}

describe('ResourceUsage', () => {
  afterEach(cleanup);

  it('renders CPU, memory and disk with used, total, unit and percentage', () => {
    render(<ResourceUsage resources={resources} />);
    expect(screen.getByText('Resource Usage')).toBeDefined();
    expect(screen.getByText('CPU')).toBeDefined();
    expect(screen.getByText('Memory')).toBeDefined();
    expect(screen.getByText('Disk')).toBeDefined();
    expect(screen.getByText('2.4 / 8.0 cores')).toBeDefined();
    expect(screen.getByText('4096.0 / 16384.0 MB')).toBeDefined();
    expect(screen.getByText('120.0 / 500.0 GB')).toBeDefined();
    expect(screen.getByText('30.0% used')).toBeDefined();
    expect(screen.getByText('25.0% used')).toBeDefined();
    expect(screen.getByText('24.0% used')).toBeDefined();
  });

  it('sizes each bar to its percentage', () => {
    const { container } = render(<ResourceUsage resources={resources} />);
    expect(bars(container).map((b) => b.style.width)).toEqual(['30%', '25%', '24%']);
  });

  it('colours the bar green up to 60%, yellow above 60% and red above 80%', () => {
    const { container } = render(
      <ResourceUsage
        resources={{
          cpu: { used: 6, total: 10 },
          memory: { usedMB: 61, totalMB: 100 },
          disk: { usedGB: 81, totalGB: 100 },
        }}
      />,
    );
    const [cpu, memory, disk] = bars(container);
    expect(cpu.className).toContain('bg-green-600');
    expect(memory.className).toContain('bg-yellow-600');
    expect(disk.className).toContain('bg-red-600');
  });

  it('keeps exactly 80% yellow', () => {
    const { container } = render(
      <ResourceUsage resources={{ ...resources, cpu: { used: 8, total: 10 } }} />,
    );
    expect(bars(container)[0].className).toContain('bg-yellow-600');
  });

  it('shows 0% and no NaN when a total is zero', () => {
    const { container } = render(
      <ResourceUsage
        resources={{
          cpu: { used: 0, total: 0 },
          memory: { usedMB: 0, totalMB: 0 },
          disk: { usedGB: 5, totalGB: 0 },
        }}
      />,
    );
    expect(screen.queryByText(/NaN/)).toBeNull();
    expect(screen.queryByText(/Infinity/)).toBeNull();
    expect(screen.getAllByText('0.0% used').length).toBe(3);
    expect(bars(container).map((b) => b.style.width)).toEqual(['0%', '0%', '0%']);
  });

  it('caps the bar and the percentage at 100% when used exceeds total', () => {
    const { container } = render(
      <ResourceUsage resources={{ ...resources, cpu: { used: 12, total: 8 } }} />,
    );
    expect(bars(container)[0].style.width).toBe('100%');
    expect(screen.getByText('100.0% used')).toBeDefined();
    expect(bars(container)[0].className).toContain('bg-red-600');
  });

  it('floors a negative used value at 0%', () => {
    const { container } = render(
      <ResourceUsage resources={{ ...resources, disk: { usedGB: -5, totalGB: 500 } }} />,
    );
    expect(bars(container)[2].style.width).toBe('0%');
    expect(screen.getByText('0.0% used')).toBeDefined();
  });
});
