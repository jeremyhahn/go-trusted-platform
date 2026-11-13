import * as React from 'react';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// #1754 review round 2: a response that answers a superseded request (an
// earlier template id, or a device identity the operator has since changed)
// never reaches the screen.

interface Deferred<T> {
  promise: Promise<T>;
  resolve: (value: T) => void;
  reject: (err: unknown) => void;
}

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  let reject!: (err: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

const actions = vi.hoisted(() => {
  const mutation = () => ({ mutate: vi.fn(), mutateAsync: vi.fn(), isLoading: false });
  return {
    getTemplate: mutation(),
    findConfig: mutation(),
    assign: mutation(),
    unassign: mutation(),
    updateTemplate: mutation(),
    deleteTemplate: mutation(),
    createProfile: mutation(),
  };
});

const toast = vi.hoisted(() => vi.fn());

vi.mock('@/components/ui/dialog', () => ({
  Dialog: ({ open, children }: { open: boolean; children?: React.ReactNode }) =>
    open ? <div role="dialog">{children}</div> : null,
  DialogTitle: ({ children }: { children?: React.ReactNode }) => <h2>{children}</h2>,
  DialogContent: ({ children }: { children?: React.ReactNode }) => <>{children}</>,
  DialogHeader: ({ children }: { children?: React.ReactNode }) => <>{children}</>,
  DialogFooter: ({ children }: { children?: React.ReactNode }) => <>{children}</>,
  DialogDescription: ({ children }: { children?: React.ReactNode }) => <>{children}</>,
}));

vi.mock('@/hooks', () => ({
  useToast: () => ({ toast }),
  useDeviceTemplateActions: () => actions,
}));

import { ProfileAssignmentPanel, TemplateDetailsDialog } from './template-dialogs';

describe('template dialogs reject superseded responses', () => {
  let templateCalls: Map<string, Deferred<unknown>>;
  let lookupCalls: Deferred<unknown>[];

  beforeEach(() => {
    templateCalls = new Map();
    lookupCalls = [];
    actions.getTemplate.mutateAsync.mockImplementation((id: string) => {
      const d = deferred<unknown>();
      templateCalls.set(id, d);
      return d.promise;
    });
    actions.getTemplate.mutate.mockImplementation((id: string) => {
      void actions.getTemplate.mutateAsync(id).catch(() => undefined);
    });
    actions.findConfig.mutateAsync.mockImplementation(() => {
      const d = deferred<unknown>();
      lookupCalls.push(d);
      return d.promise;
    });
  });

  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  it('a superseded template response never shows in the open dialog', async () => {
    const props = { onOpenChange: vi.fn(), onOpenPage: vi.fn() };
    const { rerender } = render(<TemplateDetailsDialog templateId="A" {...props} />);
    rerender(<TemplateDetailsDialog templateId={null} {...props} />);
    rerender(<TemplateDetailsDialog templateId="B" {...props} />);

    await act(async () => {
      templateCalls.get('B')?.resolve({ id: 'B', name: 'tmpl-b', role: 'edge', config: {} });
    });
    expect(screen.getByText('tmpl-b')).toBeDefined();

    await act(async () => {
      templateCalls.get('A')?.resolve({ id: 'A', name: 'tmpl-a', role: 'edge', config: {} });
    });
    expect(screen.queryByText('tmpl-a')).toBeNull();
    expect(screen.getByText('tmpl-b')).toBeDefined();
  });

  it('a lookup answered after the identity changed is discarded', async () => {
    render(<ProfileAssignmentPanel />);
    fireEvent.change(screen.getByLabelText('EK Serial Number'), { target: { value: 'ek-a' } });
    fireEvent.click(screen.getByRole('button', { name: /Find Config/ }));
    fireEvent.change(screen.getByLabelText('EK Serial Number'), { target: { value: 'ek-b' } });

    await act(async () => {
      lookupCalls[0]?.resolve({ id: '42', name: 'prof-a' });
    });

    expect((screen.getByLabelText('Profile ID') as HTMLInputElement).value).toBe('');
    expect(screen.queryByTestId('find-config-result')).toBeNull();
  });

  it('a lookup for the current identity fills the profile', async () => {
    render(<ProfileAssignmentPanel />);
    fireEvent.change(screen.getByLabelText('EK Serial Number'), { target: { value: 'ek-a' } });
    fireEvent.click(screen.getByRole('button', { name: /Find Config/ }));

    await act(async () => {
      lookupCalls[0]?.resolve({ id: '42', name: 'prof-a' });
    });

    expect((screen.getByLabelText('Profile ID') as HTMLInputElement).value).toBe('42');
    expect(screen.getByTestId('find-config-result').textContent).toContain('prof-a');
  });

  // #1754 review round 4 (P1): a lookup answered after the operator typed a
  // Profile ID never replaces it, and the unassign confirmation acts on the
  // profile it named when it opened.
  it('a lookup answered after a manual Profile ID edit leaves the unassign target alone', async () => {
    render(<ProfileAssignmentPanel />);
    fireEvent.change(screen.getByLabelText('EK Serial Number'), { target: { value: 'ek-a' } });
    fireEvent.click(screen.getByRole('button', { name: /Find Config/ }));
    fireEvent.change(screen.getByLabelText('Profile ID'), { target: { value: '7' } });
    fireEvent.click(screen.getByRole('button', { name: /Unassign Profile/ }));

    await act(async () => {
      lookupCalls[0]?.resolve({ id: '42', name: 'prof-a' });
    });

    expect((screen.getByLabelText('Profile ID') as HTMLInputElement).value).toBe('7');
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /^Unassign$/ }));
    });
    expect(actions.unassign.mutateAsync).toHaveBeenCalledWith('7');
  });

  // #1754 review round 4 (P2): useMutation rejects with a plain MutationError
  // object ({ message, code, status }), not an Error; its message is shown.
  it('a rejected lookup shows the MutationError message', async () => {
    render(<ProfileAssignmentPanel />);
    fireEvent.change(screen.getByLabelText('EK Serial Number'), { target: { value: 'ek-a' } });
    fireEvent.click(screen.getByRole('button', { name: /Find Config/ }));

    await act(async () => {
      lookupCalls[0]?.reject({ message: 'ek serial is malformed', code: 'BAD_REQUEST', status: 400 });
    });

    expect(toast).toHaveBeenCalledWith(
      expect.objectContaining({ title: 'Config lookup failed', description: 'ek serial is malformed' }),
    );
  });
});
