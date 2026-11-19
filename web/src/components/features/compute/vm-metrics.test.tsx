import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';

import type { VMMetrics } from '@/types/infrastructure';
import { VMMetricsCard } from './vm-metrics';

function metrics(overrides: Partial<VMMetrics> = {}): VMMetrics {
  return {
    cpuUsagePercent: 42.345,
    memoryUsagePercent: 61.05,
    diskUsagePercent: 7,
    networkInMbps: 12.3456,
    networkOutMbps: 0.5,
    ...overrides,
  };
}

// The bar's fill is the indicator's translateX: 100 - value percent hidden.
function fills(container: HTMLElement): string[] {
  return Array.from(container.querySelectorAll<HTMLElement>('[role="progressbar"] > div')).map(
    (el) => el.style.transform
  );
}

describe('VMMetricsCard', () => {
  afterEach(() => {
    cleanup();
  });

  it('labels each metric', () => {
    render(<VMMetricsCard metrics={metrics()} />);

    for (const label of ['Performance Metrics', 'CPU Usage', 'Memory Usage', 'Disk Usage', 'Network In', 'Network Out']) {
      expect(screen.getByText(label)).toBeDefined();
    }
  });

  it('rounds percentages to one decimal and throughput to two', () => {
    render(<VMMetricsCard metrics={metrics()} />);

    expect(screen.getByText('42.3%')).toBeDefined();
    expect(screen.getByText('61.0%')).toBeDefined();
    expect(screen.getByText('7.0%')).toBeDefined();
    expect(screen.getByText('12.35 Mbps')).toBeDefined();
    expect(screen.getByText('0.50 Mbps')).toBeDefined();
  });

  it('draws a bar for CPU, memory and disk, filled to each percentage', () => {
    const { container } = render(<VMMetricsCard metrics={metrics({ cpuUsagePercent: 40, memoryUsagePercent: 75 })} />);

    expect(screen.getAllByRole('progressbar')).toHaveLength(3);
    expect(fills(container)).toEqual(['translateX(-60%)', 'translateX(-25%)', 'translateX(-93%)']);
  });

  it('shows an idle VM as zeros with empty bars', () => {
    const { container } = render(
      <VMMetricsCard
        metrics={{ cpuUsagePercent: 0, memoryUsagePercent: 0, diskUsagePercent: 0, networkInMbps: 0, networkOutMbps: 0 }}
      />
    );

    expect(screen.getAllByText('0.0%')).toHaveLength(3);
    expect(screen.getAllByText('0.00 Mbps')).toHaveLength(2);
    expect(fills(container)).toEqual(['translateX(-100%)', 'translateX(-100%)', 'translateX(-100%)']);
  });

  it('shows a saturated VM as full bars', () => {
    const { container } = render(
      <VMMetricsCard metrics={metrics({ cpuUsagePercent: 100, memoryUsagePercent: 100, diskUsagePercent: 100 })} />
    );

    expect(screen.getAllByText('100.0%')).toHaveLength(3);
    expect(fills(container)).toEqual(['translateX(-0%)', 'translateX(-0%)', 'translateX(-0%)']);
  });

  it('prints a non-finite reading as NaN rather than throwing', () => {
    render(<VMMetricsCard metrics={metrics({ cpuUsagePercent: Number.NaN, networkInMbps: Number.NaN })} />);

    expect(screen.getByText('NaN%')).toBeDefined();
    expect(screen.getByText('NaN Mbps')).toBeDefined();
  });
});
