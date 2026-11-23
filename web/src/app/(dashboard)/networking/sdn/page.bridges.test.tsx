import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// #2064: the SDN page lists bridges through useSDN (network boundary, mocked
// here) and offers Details (GetBridge) and Delete (DeleteBridge) per bridge,
// each behind the capability gate of its route.

const GET_OP = 'GET /api/v1/sdn/bridges/{name}';
const DELETE_OP = 'DELETE /api/v1/sdn/bridges/{name}';

const { sdn, toast, off } = vi.hoisted(() => ({
  sdn: {
    listBridges: vi.fn(),
    listFlows: vi.fn(),
    getBridge: vi.fn(),
    deleteBridge: vi.fn(),
    createBridge: vi.fn(),
  },
  toast: vi.fn(),
  off: new Set<string>(),
}));

vi.mock('@/hooks', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/hooks')>()),
  useSDN: () => sdn,
}));

vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast }) }));

vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({
    loading: false,
    error: undefined,
    capability: (op: string) =>
      off.has(op) ? { enabled: false, reason: 'not-configured: sdn' } : { enabled: true },
  }),
}));

vi.mock('@/components/features/networking/sdn-topology', () => ({
  SDNTopology: () => <div data-testid="topology" />,
}));

import SDNPage from './page';

const brInt = {
  id: 'br-int',
  config: { name: 'br-int', type: 'BRIDGE_TYPE_OVS' },
  status: 'BRIDGE_STATUS_ACTIVE',
  createdAt: '2026-11-01T00:00:00Z',
};

beforeEach(() => {
  off.clear();
  sdn.listBridges.mockReset().mockResolvedValue({ bridges: [brInt] });
  sdn.listFlows.mockReset().mockResolvedValue({ flows: [] });
  sdn.getBridge.mockReset();
  sdn.deleteBridge.mockReset();
  sdn.createBridge.mockReset();
  toast.mockReset();
});

afterEach(() => cleanup());

async function renderPage() {
  render(<SDNPage />);
  return screen.findByRole('button', { name: 'Details br-int' });
}

describe('SDN page bridge actions', () => {
  it('offers Details and Delete per bridge, each gated on its route', async () => {
    const details = await renderPage();
    const del = screen.getByRole('button', { name: 'Delete br-int' });
    expect(details).toHaveAttribute('data-capability-op', GET_OP);
    expect(del).toHaveAttribute('data-capability-op', DELETE_OP);
    expect(details).toBeEnabled();
    expect(del).toBeEnabled();
    cleanup();

    off.add(GET_OP);
    await renderPage();
    expect(screen.getByRole('button', { name: 'Details br-int' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Delete br-int' })).toBeEnabled();
    cleanup();

    off.clear();
    off.add(DELETE_OP);
    await renderPage();
    expect(screen.getByRole('button', { name: 'Details br-int' })).toBeEnabled();
    expect(screen.getByRole('button', { name: 'Delete br-int' })).toBeDisabled();
  });

  it('shows the bridge read from getBridge in a dialog', async () => {
    sdn.getBridge.mockResolvedValue({ bridge: { ...brInt, ports: ['p1'] } });
    fireEvent.click(await renderPage());
    const detail = await screen.findByTestId('sdn-bridge-detail');
    expect(sdn.getBridge).toHaveBeenCalledWith('br-int');
    expect(detail).toHaveTextContent('br-int');
  });

  it('shows a refused getBridge inline', async () => {
    sdn.getBridge.mockRejectedValue(new Error('HTTP 404: not found'));
    fireEvent.click(await renderPage());
    const err = await screen.findByTestId('sdn-bridge-detail-error');
    expect(err).toHaveTextContent('HTTP 404: not found');
  });

  it('deletes a bridge only after the confirm and lists again', async () => {
    sdn.deleteBridge.mockResolvedValue({});
    await renderPage();
    fireEvent.click(screen.getByRole('button', { name: 'Delete br-int' }));
    const dialog = await screen.findByRole('dialog');
    expect(dialog).toHaveTextContent('Delete bridge br-int?');
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(sdn.deleteBridge).not.toHaveBeenCalled();

    const listed = sdn.listBridges.mock.calls.length;
    fireEvent.click(screen.getByRole('button', { name: 'Delete br-int' }));
    const again = await screen.findByRole('dialog');
    fireEvent.click(within(again).getByRole('button', { name: 'Delete' }));
    await waitFor(() => expect(sdn.deleteBridge).toHaveBeenCalledWith('br-int'));
    await waitFor(() => expect(sdn.listBridges.mock.calls.length).toBeGreaterThan(listed));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
  });

  it('shows a refused delete in the dialog', async () => {
    sdn.deleteBridge.mockRejectedValue(new Error('HTTP 409: bridge has ports'));
    await renderPage();
    fireEvent.click(screen.getByRole('button', { name: 'Delete br-int' }));
    const dialog = await screen.findByRole('dialog');
    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' }));
    expect(await within(dialog).findByText('HTTP 409: bridge has ports')).toBeInTheDocument();
    expect(screen.getByRole('dialog')).toBeInTheDocument();
  });
});
