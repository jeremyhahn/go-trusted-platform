import * as React from 'react';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { DataTableRowActions } from './data-table-row-actions';

const { off } = vi.hoisted(() => ({ off: new Set<string>() }));

vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({
    loading: false,
    error: undefined,
    capability: (op: string) =>
      off.has(op) ? { enabled: false, reason: 'not-configured: gateway' } : { enabled: true },
  }),
}));

// The menu renders its items inline so each item's props are visible
// without driving the Radix pointer events.
vi.mock('@/components/ui/dropdown-menu', () => ({
  DropdownMenu: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  DropdownMenuTrigger: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  DropdownMenuContent: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  DropdownMenuSeparator: () => <hr />,
  DropdownMenuItem: (props: React.ButtonHTMLAttributes<HTMLButtonElement>) => (
    <button role="menuitem" {...props} />
  ),
}));

// #2051: a row action may name the route it calls; the item then carries
// the capability gate for that route.
const DELETE_OP = 'DELETE /api/v1/sdn/gateway/ipam/pools/{id}';

function item(name: string) {
  return screen.getByRole('menuitem', { name }) as HTMLButtonElement;
}

describe('DataTableRowActions capability gate', () => {
  afterEach(() => {
    cleanup();
    off.clear();
  });

  it('gates an action that names an op and withholds it when not offered', () => {
    off.add(DELETE_OP);
    const onDelete = vi.fn();
    render(
      <DataTableRowActions
        row={{ id: 'pool-a' }}
        actions={[{ label: 'Delete', onClick: onDelete, variant: 'destructive', op: DELETE_OP }]}
      />,
    );

    const del = item('Delete');
    expect(del.getAttribute('data-capability-op')).toBe(DELETE_OP);
    expect(del.getAttribute('data-capability-enabled')).toBe('false');
    expect(del.disabled).toBe(true);
    expect(del.getAttribute('title')).toBe('not-configured: gateway');
  });

  it('offers a gated action when the server offers its op', () => {
    const onDelete = vi.fn();
    render(
      <DataTableRowActions
        row={{ id: 'pool-a' }}
        actions={[{ label: 'Delete', onClick: onDelete, op: DELETE_OP }]}
      />,
    );

    const del = item('Delete');
    expect(del.getAttribute('data-capability-op')).toBe(DELETE_OP);
    expect(del.getAttribute('data-capability-enabled')).toBe('true');
    expect(del.disabled).toBe(false);
    fireEvent.click(del);
    expect(onDelete).toHaveBeenCalledWith({ id: 'pool-a' });
  });

  it('renders an action without op as before, with no gate', () => {
    const onView = vi.fn();
    render(<DataTableRowActions row={{ id: 'pool-a' }} actions={[{ label: 'View', onClick: onView }]} />);

    const view = item('View');
    expect(view.hasAttribute('data-capability-op')).toBe(false);
    expect(view.hasAttribute('data-capability-enabled')).toBe(false);
    expect(view.disabled).toBe(false);
    expect(view.hasAttribute('title')).toBe(false);
    fireEvent.click(view);
    expect(onView).toHaveBeenCalledWith({ id: 'pool-a' });
  });
});
