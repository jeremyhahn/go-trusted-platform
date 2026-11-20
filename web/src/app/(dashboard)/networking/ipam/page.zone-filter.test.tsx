import type { ReactNode } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';

type Reply = { success: boolean; data?: unknown };

const sdk = vi.hoisted(() => ({
  listIPAMPools: null as null | (() => Promise<{ success: boolean; data?: unknown }>),
}));

vi.mock('trusted-platform-sdk', async (importOriginal) => ({
  ...(await importOriginal<typeof import('trusted-platform-sdk')>()),
  useGateway: () => ({
    listIPAMPools: () => sdk.listIPAMPools!(),
  }),
}));

import IPAMPage from './page';

vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }));
vi.mock('@/components/ui/select', () => ({
  Select: ({
    value,
    onValueChange,
    children,
  }: {
    value: string;
    onValueChange: (v: string) => void;
    children: ReactNode;
  }) => (
    <select aria-label="Zone" value={value} onChange={(e) => onValueChange(e.target.value)}>
      {children}
    </select>
  ),
  SelectItem: ({ value, children }: { value: string; children: ReactNode }) => (
    <option value={value}>{children}</option>
  ),
  SelectTrigger: () => null,
  SelectValue: () => null,
  SelectContent: ({ children }: { children: ReactNode }) => <>{children}</>,
}));

function pool(n: number) {
  return {
    id: `pool-${n}`,
    name: `pool-z${n}`,
    cidr: `192.0.2.${(n - 1) * 64}/26`,
    gateway: `192.0.2.${(n - 1) * 64 + 1}`,
    zone: `z${n}`,
    description: `zone ${n} pool`,
    total: '62',
    allocated: '2',
    available: '60',
    default_lease_duration_nanos: 3600000000000,
    inactivity_timeout_nanos: 600000000000,
    reserved: [`192.0.2.${(n - 1) * 64 + 1}/32`],
    range_start: `192.0.2.${(n - 1) * 64 + 10}`,
    range_end: `192.0.2.${(n - 1) * 64 + 60}`,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
  };
}

function ok(body: unknown): Reply {
  return { success: true, data: body };
}

afterEach(() => {
  cleanup();
  sdk.listIPAMPools = null;
});

describe('IPAMPage zone filter', () => {
  it("changing the zone hides the previous zone's pools until the new read answers", async () => {
    let answerZ2: (r: Reply) => void = () => {};
    let reads = 0;
    // The first read answers with both zones; the read the zone change
    // starts stays pending until the test answers it.
    sdk.listIPAMPools = () => {
      reads += 1;
      if (reads > 1) {
        return new Promise<Reply>((resolve) => {
          answerZ2 = resolve;
        });
      }
      return Promise.resolve(ok({ pools: [pool(1), pool(2)] }));
    };

    render(<IPAMPage />);
    await screen.findByText('pool-z1');

    const zoneSelect = screen
      .getAllByLabelText('Zone')
      .find((el) => Array.from((el as HTMLSelectElement).options).some((o) => o.value === 'z2'));
    expect(zoneSelect).toBeTruthy();
    fireEvent.change(zoneSelect!, { target: { value: 'z2' } });

    expect(screen.queryByText('pool-z1')).toBeNull();

    answerZ2(ok({ pools: [pool(1), pool(2)] }));
    expect(await screen.findByText('pool-z2')).toBeTruthy();
    expect(screen.queryByText('pool-z1')).toBeNull();
  });
});
