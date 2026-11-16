import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';

import type { ServiceHealth, ServiceStatus } from '@/types/platform';
import { ServiceHealthCard } from './service-health-card';

const base: ServiceHealth = {
  name: 'API Server',
  status: 'up',
  uptime: 86400,
  latencyMs: 45,
  lastCheck: '2025-01-19T10:00:00Z',
};

describe('ServiceHealthCard', () => {
  afterEach(cleanup);

  it('renders the name, last check, uptime and latency', () => {
    render(<ServiceHealthCard service={base} />);
    expect(screen.getByText('API Server')).toBeDefined();
    expect(
      screen.getByText(`Last checked: ${new Date(base.lastCheck).toLocaleTimeString()}`),
    ).toBeDefined();
    expect(screen.getByText('Uptime')).toBeDefined();
    expect(screen.getByText('1d 0h')).toBeDefined();
    expect(screen.getByText('Latency')).toBeDefined();
    expect(screen.getByText('45ms')).toBeDefined();
  });

  it.each([
    ['up', 'Up', 'bg-green-100'],
    ['degraded', 'Degraded', 'bg-yellow-100'],
    ['down', 'Down', 'bg-red-100'],
  ] as const)('renders the %s badge', (status, label, cls) => {
    render(<ServiceHealthCard service={{ ...base, status }} />);
    expect(screen.getByText(label).className).toContain(cls);
  });

  it.each([
    [0, '0m'],
    [59, '0m'],
    [60, '1m'],
    [3599, '59m'],
    [3600, '1h 0m'],
    [3660, '1h 1m'],
    [86399, '23h 59m'],
    [86400, '1d 0h'],
    [90000, '1d 1h'],
    [10 * 86400 + 5 * 3600 + 30, '10d 5h'],
  ])('formats an uptime of %i seconds as %s', (uptime, text) => {
    render(<ServiceHealthCard service={{ ...base, uptime }} />);
    expect(screen.getByText(text)).toBeDefined();
  });

  it.each([
    ['negative', -120],
    ['NaN', Number.NaN],
    ['infinite', Number.POSITIVE_INFINITY],
  ])('formats a %s uptime as 0m', (_name, uptime) => {
    render(<ServiceHealthCard service={{ ...base, uptime }} />);
    expect(screen.getByText('0m')).toBeDefined();
    expect(screen.queryByText(/-|NaN|Infinity/)).toBeNull();
  });

  it('shows the error block only when an error is set', () => {
    render(<ServiceHealthCard service={{ ...base, status: 'down', error: 'connection refused' }} />);
    expect(screen.getByText('connection refused')).toBeDefined();
    cleanup();
    render(<ServiceHealthCard service={{ ...base, error: '' }} />);
    expect(screen.queryByText('connection refused')).toBeNull();
    expect(document.querySelector('.bg-destructive\\/10')).toBeNull();
  });

  it('renders an unknown status as Unknown instead of crashing', () => {
    render(<ServiceHealthCard service={{ ...base, status: 'starting' as ServiceStatus }} />);
    expect(screen.getByText('Unknown')).toBeDefined();
  });

  it('renders an invalid last check without throwing', () => {
    render(<ServiceHealthCard service={{ ...base, lastCheck: 'garbage' }} />);
    expect(screen.getByText('Last checked: Invalid Date')).toBeDefined();
  });
});
