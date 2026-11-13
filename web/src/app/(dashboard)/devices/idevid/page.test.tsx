import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { ReactNode } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const { toast } = vi.hoisted(() => ({ toast: vi.fn() }));

vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast }) }));
vi.mock('@/hooks', () => ({ useIDevID: () => ({}) }));

vi.mock('@/components/features/devices/idevid-table', () => ({
  IDevIDTable: ({ idevids, onIDevIDChange }: { idevids: { id: string }[]; onIDevIDChange: () => void }) => (
    <div data-testid="idevid-table">
      <span data-testid="idevid-count">{idevids.length}</span>
      {idevids.map((i) => (
        <span key={i.id}>{i.id}</span>
      ))}
      <button onClick={onIDevIDChange}>table-refresh</button>
    </div>
  ),
}));

vi.mock('@/components/features/devices/idevid-form', () => ({
  IDevIDForm: ({ onSuccess, onCancel }: { onSuccess: () => void; onCancel: () => void }) => (
    <div>
      <button onClick={onSuccess}>form-success</button>
      <button onClick={onCancel}>form-cancel</button>
    </div>
  ),
}));

// Radix Select does not open in jsdom; a native select keeps the page's
// value / onValueChange contract testable.
vi.mock('@/components/ui/select', () => ({
  Select: ({ value, onValueChange, children }: { value: string; onValueChange: (v: string) => void; children: ReactNode }) => (
    <select data-testid="select" value={value} onChange={(e) => onValueChange(e.target.value)}>
      {children}
    </select>
  ),
  SelectTrigger: () => null,
  SelectValue: () => null,
  SelectContent: ({ children }: { children: ReactNode }) => <>{children}</>,
  SelectItem: ({ value, children }: { value: string; children: ReactNode }) => <option value={value}>{children}</option>,
}));

import IDevIDPage from './page';

type Reply = { ok: boolean; body?: unknown } | Error | 'pending';

let listReply: Reply;
let expiringReply: Reply;
let fetchMock: ReturnType<typeof vi.fn>;

function respond(reply: Reply): Promise<unknown> {
  if (reply === 'pending') return new Promise(() => {});
  if (reply instanceof Error) return Promise.reject(reply);
  return Promise.resolve({ ok: reply.ok, json: () => Promise.resolve(reply.body) });
}

function listCalls(): number {
  return fetchMock.mock.calls.filter(([url]) => url === '/api/v1/idevid').length;
}

beforeEach(() => {
  toast.mockReset();
  listReply = { ok: true, body: { idevids: [{ id: 'cert-a' }, { id: 'cert-b' }] } };
  expiringReply = { ok: true, body: { count: 0 } };
  fetchMock = vi.fn((url: string) => respond(url === '/api/v1/idevid/expiring' ? expiringReply : listReply));
  vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

async function renderLoaded() {
  render(<IDevIDPage />);
  await waitFor(() => expect(screen.getByTestId('idevid-table')).toBeTruthy());
}

describe('IDevIDPage', () => {
  it('shows the loading state while the list request is pending', () => {
    listReply = 'pending';
    render(<IDevIDPage />);
    expect(screen.getByText('Loading certificates...')).toBeTruthy();
    expect(screen.queryByTestId('idevid-table')).toBeNull();
  });

  it('fetches the list and the expiring count on mount and renders the table', async () => {
    await renderLoaded();
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/idevid');
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/idevid/expiring');
    expect(screen.getByTestId('idevid-count').textContent).toBe('2');
    expect(screen.getByText('cert-a')).toBeTruthy();
    expect(screen.queryByText('Certificates Expiring Soon')).toBeNull();
  });

  it('treats a response without idevids as an empty list', async () => {
    listReply = { ok: true, body: {} };
    await renderLoaded();
    expect(screen.getByTestId('idevid-count').textContent).toBe('0');
    expect(toast).not.toHaveBeenCalled();
  });

  it('toasts the error and shows an empty table when the list request fails', async () => {
    listReply = { ok: false };
    await renderLoaded();
    expect(screen.getByTestId('idevid-count').textContent).toBe('0');
    expect(toast).toHaveBeenCalledWith({
      title: 'Error',
      description: 'Failed to fetch IDevID certificates',
      variant: 'destructive',
    });
  });

  it('toasts the error message of a rejected list request', async () => {
    listReply = new Error('network down');
    await renderLoaded();
    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ description: 'network down', variant: 'destructive' }));
  });

  it('falls back to the default message when the rejection is not an Error', async () => {
    fetchMock.mockImplementation((url: string) =>
      url === '/api/v1/idevid' ? Promise.reject('boom') : respond(expiringReply),
    );
    await renderLoaded();
    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ description: 'Failed to fetch IDevID certificates' }));
  });

  it('warns about one expiring certificate in the singular', async () => {
    expiringReply = { ok: true, body: { count: 1 } };
    await renderLoaded();
    await waitFor(() => expect(screen.getByText('Certificates Expiring Soon')).toBeTruthy());
    expect(screen.getByText(/1 certificate will expire within the next 30 days/)).toBeTruthy();
  });

  it('warns about several expiring certificates in the plural', async () => {
    expiringReply = { ok: true, body: { count: 3 } };
    await renderLoaded();
    await waitFor(() => expect(screen.getByText(/3 certificates will expire/)).toBeTruthy());
  });

  it('shows no warning when the expiring count is missing or the request is not ok', async () => {
    expiringReply = { ok: true, body: {} };
    await renderLoaded();
    expect(screen.queryByText('Certificates Expiring Soon')).toBeNull();
    cleanup();
    expiringReply = { ok: false };
    await renderLoaded();
    expect(screen.queryByText('Certificates Expiring Soon')).toBeNull();
  });

  it('logs and swallows a rejected expiring request without a toast', async () => {
    const err = vi.spyOn(console, 'error').mockImplementation(() => {});
    expiringReply = new Error('offline');
    await renderLoaded();
    await waitFor(() => expect(err).toHaveBeenCalledWith('Failed to fetch expiring certificates:', expect.any(Error)));
    expect(toast).not.toHaveBeenCalled();
    expect(screen.queryByText('Certificates Expiring Soon')).toBeNull();
  });

  it('refetches when a filter changes and shows Clear filters until it is cleared', async () => {
    await renderLoaded();
    expect(screen.queryByText('Clear filters')).toBeNull();
    const before = listCalls();

    fireEvent.change(screen.getByPlaceholderText('Search certificates...'), { target: { value: 'abc' } });
    await waitFor(() => expect(listCalls()).toBe(before + 1));
    expect((screen.getByPlaceholderText('Search certificates...') as HTMLInputElement).value).toBe('abc');
    expect(screen.getByText('Clear filters')).toBeTruthy();

    fireEvent.click(screen.getByText('Clear filters'));
    await waitFor(() => expect(screen.queryByText('Clear filters')).toBeNull());
    expect((screen.getByPlaceholderText('Search certificates...') as HTMLInputElement).value).toBe('');
  });

  it('drops an emptied search back to no filter', async () => {
    await renderLoaded();
    const input = screen.getByPlaceholderText('Search certificates...');
    fireEvent.change(input, { target: { value: 'x' } });
    expect(screen.getByText('Clear filters')).toBeTruthy();
    fireEvent.change(input, { target: { value: '' } });
    expect(screen.queryByText('Clear filters')).toBeNull();
  });

  it('sets and resets the status filter, with "all" meaning no filter', async () => {
    await renderLoaded();
    const [status] = screen.getAllByTestId('select') as HTMLSelectElement[];
    expect(status.value).toBe('all');
    fireEvent.change(status, { target: { value: 'revoked' } });
    expect(status.value).toBe('revoked');
    expect(screen.getByText('Clear filters')).toBeTruthy();
    fireEvent.change(status, { target: { value: 'all' } });
    expect(status.value).toBe('all');
    expect(screen.queryByText('Clear filters')).toBeNull();
  });

  it('parses the expiration filter to days and clears it on "all"', async () => {
    await renderLoaded();
    const expiry = screen.getAllByTestId('select')[1] as HTMLSelectElement;
    expect(expiry.value).toBe('all');
    fireEvent.change(expiry, { target: { value: '90' } });
    expect(expiry.value).toBe('90');
    expect(screen.getByText('Clear filters')).toBeTruthy();
    fireEvent.change(expiry, { target: { value: 'all' } });
    expect(expiry.value).toBe('all');
    expect(screen.queryByText('Clear filters')).toBeNull();
  });

  it('refetches the list when the table reports a change', async () => {
    await renderLoaded();
    const before = listCalls();
    await act(async () => {
      fireEvent.click(screen.getByText('table-refresh'));
    });
    await waitFor(() => expect(listCalls()).toBe(before + 1));
  });

  it('opens the issue dialog, closes it on cancel without a refetch', async () => {
    await renderLoaded();
    expect(screen.queryByText('Issue IDevID Certificate')).toBeNull();
    fireEvent.click(screen.getByText('Issue IDevID'));
    expect(screen.getByText('Issue IDevID Certificate')).toBeTruthy();
    const before = listCalls();
    fireEvent.click(screen.getByText('form-cancel'));
    await waitFor(() => expect(screen.queryByText('Issue IDevID Certificate')).toBeNull());
    expect(listCalls()).toBe(before);
  });

  it('closes the dialog and refetches the list after a successful issue', async () => {
    await renderLoaded();
    fireEvent.click(screen.getByText('Issue IDevID'));
    const before = listCalls();
    await act(async () => {
      fireEvent.click(screen.getByText('form-success'));
    });
    await waitFor(() => expect(screen.queryByText('Issue IDevID Certificate')).toBeNull());
    await waitFor(() => expect(listCalls()).toBe(before + 1));
  });
});
