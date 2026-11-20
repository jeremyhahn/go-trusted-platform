import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { cleanup, render, screen, fireEvent } from '@testing-library/react';
import type { PerfCard } from '@/hooks/use-gateway-perf';

const hook = {
  flows: { data: undefined, error: undefined, loading: false } as PerfCard,
  datapath: { data: undefined, error: undefined, loading: false } as PerfCard,
  conntrack: { data: undefined, error: undefined, loading: false } as PerfCard,
  runFlows: vi.fn(),
  loadDatapath: vi.fn(),
  loadConntrack: vi.fn(),
};

vi.mock('@/hooks/use-gateway-perf', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/hooks/use-gateway-perf')>()),
  useGatewayPerf: () => hook,
}));

import GatewayPerfPage from './page';

describe('GatewayPerfPage', () => {
  afterEach(cleanup);

  beforeEach(() => {
    vi.clearAllMocks();
    hook.flows = { data: { flowCount: '12' }, error: undefined, loading: false };
    hook.datapath = { data: undefined, error: new Error('no such bridge'), loading: false };
    hook.conntrack = { data: { entries: '9' }, error: undefined, loading: false };
  });

  it('renders the three cards with counters or the reason they are unavailable', () => {
    render(<GatewayPerfPage />);
    expect(screen.getByRole('heading', { name: 'Gateway performance' })).toBeTruthy();
    expect(screen.getByTestId('gateway-perf-flows').textContent).toContain('flowCount');
    expect(screen.getByTestId('gateway-perf-flows').textContent).toContain('12');
    expect(screen.getByTestId('gateway-perf-datapath').textContent).toContain(
      'unavailable: no such bridge'
    );
    expect(screen.getByTestId('gateway-perf-conntrack').textContent).toContain('entries');
  });

  it('runs the flows report', () => {
    render(<GatewayPerfPage />);
    fireEvent.click(screen.getByRole('button', { name: 'Run flows report' }));
    expect(hook.runFlows).toHaveBeenCalledTimes(1);
  });

  it('loads datapath for the typed bridge, or all bridges when empty', () => {
    render(<GatewayPerfPage />);
    fireEvent.click(screen.getByRole('button', { name: 'Load datapath' }));
    expect(hook.loadDatapath).toHaveBeenLastCalledWith(undefined);
    fireEvent.change(screen.getByLabelText('Bridge'), { target: { value: 'br-int' } });
    fireEvent.click(screen.getByRole('button', { name: 'Load datapath' }));
    expect(hook.loadDatapath).toHaveBeenLastCalledWith('br-int');
  });

  it('loads conntrack for an optional zone and refuses a bad one', () => {
    render(<GatewayPerfPage />);
    fireEvent.click(screen.getByRole('button', { name: 'Load conntrack' }));
    expect(hook.loadConntrack).toHaveBeenLastCalledWith();
    fireEvent.change(screen.getByLabelText('Zone'), { target: { value: '7' } });
    fireEvent.click(screen.getByRole('button', { name: 'Load conntrack' }));
    expect(hook.loadConntrack).toHaveBeenLastCalledWith(7);
    fireEvent.change(screen.getByLabelText('Zone'), { target: { value: 'abc' } });
    fireEvent.click(screen.getByRole('button', { name: 'Load conntrack' }));
    expect(hook.loadConntrack).toHaveBeenCalledTimes(2);
    expect(screen.getByRole('alert').textContent).toContain('Zone must be a number');
  });
});
