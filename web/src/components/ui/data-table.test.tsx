import type { ColumnDef } from '@tanstack/react-table';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { DataTable, createSelectColumn } from './data-table';

// #1821: DataTable wires @tanstack/react-table to the toolbar, the
// pagination and the row selection; createSelectColumn builds the checkbox
// column the selection and the bulk actions rely on.

type Item = { id: string; name: string; status: string };

const nameColumns: ColumnDef<Item>[] = [
  { accessorKey: 'name', header: 'Name' },
  { accessorKey: 'status', header: 'Status' },
];

function items(n: number): Item[] {
  return Array.from({ length: n }, (_, i) => ({
    id: String(i + 1),
    name: `item-${String(i + 1).padStart(2, '0')}`,
    status: i % 2 === 0 ? 'active' : 'inactive',
  }));
}

// Body rows only: the header row is inside <thead>.
function bodyRows(container: HTMLElement): HTMLTableRowElement[] {
  return Array.from(container.querySelectorAll('tbody tr'));
}

describe('DataTable', () => {
  afterEach(() => {
    cleanup();
  });

  it('renders a header per column and a cell per value', () => {
    const { container } = render(<DataTable columns={nameColumns} data={items(2)} />);

    expect(screen.getByRole('columnheader', { name: 'Name' })).toBeDefined();
    expect(screen.getByRole('columnheader', { name: 'Status' })).toBeDefined();
    expect(bodyRows(container)).toHaveLength(2);
    expect(screen.getByText('item-01')).toBeDefined();
    expect(screen.getByText('item-02')).toBeDefined();
    expect(screen.getAllByText('active')).toHaveLength(1);
  });

  it('shows "No results." for empty data, spanning every column', () => {
    const { container } = render(<DataTable columns={nameColumns} data={[]} />);

    const cell = screen.getByText('No results.');
    expect(cell.getAttribute('colspan')).toBe('2');
    expect(bodyRows(container)).toHaveLength(1);
  });

  it('shows the custom empty state instead of the default text', () => {
    render(<DataTable columns={nameColumns} data={[]} emptyState={<span>Nothing enrolled</span>} />);

    expect(screen.getByText('Nothing enrolled')).toBeDefined();
    expect(screen.queryByText('No results.')).toBeNull();
  });

  it('renders pageSize skeleton rows while loading, and no data or pagination', () => {
    const { container } = render(
      <DataTable columns={nameColumns} data={items(3)} loading pageSize={4} />
    );

    const rows = bodyRows(container);
    expect(rows).toHaveLength(4);
    for (const row of rows) {
      expect(row.querySelectorAll('td')).toHaveLength(2);
      expect(row.querySelectorAll('.animate-pulse')).toHaveLength(2);
    }
    expect(screen.queryByText('item-01')).toBeNull();
    expect(screen.queryByText('Rows per page')).toBeNull();
  });

  it('pages at 25 rows by default and reports the range', () => {
    const { container } = render(<DataTable columns={nameColumns} data={items(30)} />);

    expect(bodyRows(container)).toHaveLength(25);
    expect(container.textContent).toContain('Showing 1 to 25 of 30 results');
    expect(container.textContent).toContain('Page 1 of 2');
  });

  it('honours a custom pageSize and moves to the next page', () => {
    const { container } = render(<DataTable columns={nameColumns} data={items(5)} pageSize={2} />);

    expect(bodyRows(container)).toHaveLength(2);
    fireEvent.click(screen.getByRole('button', { name: 'Go to next page' }));
    expect(screen.getByText('item-03')).toBeDefined();
    expect(screen.queryByText('item-01')).toBeNull();
    expect(container.textContent).toContain('Page 2 of 3');
  });

  it('renders every row and no pagination controls when pagination is off', () => {
    const { container } = render(
      <DataTable columns={nameColumns} data={items(30)} pagination={false} />
    );

    expect(bodyRows(container)).toHaveLength(30);
    expect(screen.queryByText('Rows per page')).toBeNull();
  });

  it('calls onRowClick with the original row and marks rows clickable', () => {
    const onRowClick = vi.fn();
    const data = items(2);
    const { container } = render(
      <DataTable columns={nameColumns} data={data} onRowClick={onRowClick} />
    );

    fireEvent.click(screen.getByText('item-02'));

    expect(onRowClick).toHaveBeenCalledTimes(1);
    expect(onRowClick).toHaveBeenCalledWith(data[1]);
    expect(bodyRows(container)[0].className).toContain('cursor-pointer');
  });

  it('does not mark rows clickable without onRowClick', () => {
    const { container } = render(<DataTable columns={nameColumns} data={items(1)} />);

    expect(bodyRows(container)[0].className).not.toContain('cursor-pointer');
    // A click without a handler must not throw.
    fireEvent.click(screen.getByText('item-01'));
  });

  it('filters rows through the search input on searchKey', () => {
    const { container } = render(
      <DataTable
        columns={nameColumns}
        data={items(12)}
        searchKey="name"
        searchPlaceholder="Search names..."
      />
    );

    fireEvent.change(screen.getByPlaceholderText('Search names...'), {
      target: { value: 'item-1' },
    });

    expect(bodyRows(container).map((r) => r.querySelector('td')?.textContent)).toEqual([
      'item-10',
      'item-11',
      'item-12',
    ]);
  });

  it('shows "No results." when the search matches nothing', () => {
    render(<DataTable columns={nameColumns} data={items(3)} searchKey="name" />);

    fireEvent.change(screen.getByPlaceholderText('Search...'), { target: { value: 'zzz' } });

    expect(screen.getByText('No results.')).toBeDefined();
  });

  it('shows bulk actions only once a row is selected and passes the selected rows', () => {
    const onDelete = vi.fn();
    const onExport = vi.fn();
    const data = items(3);
    render(
      <DataTable
        columns={[createSelectColumn<Item>(), ...nameColumns]}
        data={data}
        bulkActions={[
          { label: 'Delete', onClick: onDelete, variant: 'destructive' },
          { label: 'Export', onClick: onExport },
        ]}
      />
    );

    expect(screen.queryByRole('button', { name: /Delete/ })).toBeNull();

    fireEvent.click(screen.getAllByRole('checkbox', { name: 'Select row' })[1]);

    fireEvent.click(screen.getByRole('button', { name: 'Delete (1)' }));
    expect(onDelete).toHaveBeenCalledWith([data[1]]);
    expect(screen.getByRole('button', { name: 'Export (1)' })).toBeDefined();
    expect(onExport).not.toHaveBeenCalled();
  });

  it('selects every page row through the header checkbox', () => {
    const onDelete = vi.fn();
    const data = items(3);
    const { container } = render(
      <DataTable
        columns={[createSelectColumn<Item>(), ...nameColumns]}
        data={data}
        bulkActions={[{ label: 'Delete', onClick: onDelete }]}
      />
    );

    fireEvent.click(screen.getByRole('checkbox', { name: 'Select all' }));

    expect(container.textContent).toContain('3 of 3 row(s) selected');
    for (const row of bodyRows(container)) {
      expect(row.getAttribute('data-state')).toBe('selected');
    }
    fireEvent.click(screen.getByRole('button', { name: 'Delete (3)' }));
    expect(onDelete).toHaveBeenCalledWith(data);
  });

  it('renders no bulk actions for an empty bulkActions list', () => {
    render(
      <DataTable
        columns={[createSelectColumn<Item>(), ...nameColumns]}
        data={items(2)}
        bulkActions={[]}
      />
    );

    fireEvent.click(screen.getByRole('checkbox', { name: 'Select all' }));

    expect(screen.queryAllByRole('button', { name: /\(\d+\)$/ })).toHaveLength(0);
  });
});

describe('createSelectColumn', () => {
  afterEach(() => {
    cleanup();
  });

  it('returns a "select" column that cannot be sorted or hidden', () => {
    const column = createSelectColumn<Item>();

    expect(column.id).toBe('select');
    expect(column.enableSorting).toBe(false);
    expect(column.enableHiding).toBe(false);
    expect(typeof column.header).toBe('function');
    expect(typeof column.cell).toBe('function');
  });

  it('returns a fresh column per call', () => {
    expect(createSelectColumn<Item>()).not.toBe(createSelectColumn<Item>());
  });

  it('marks the header checkbox mixed when only some rows are selected', () => {
    render(<DataTable columns={[createSelectColumn<Item>(), ...nameColumns]} data={items(3)} />);

    const all = screen.getByRole('checkbox', { name: 'Select all' });
    expect(all.getAttribute('aria-checked')).toBe('false');

    fireEvent.click(screen.getAllByRole('checkbox', { name: 'Select row' })[0]);
    expect(all.getAttribute('aria-checked')).toBe('mixed');

    fireEvent.click(screen.getAllByRole('checkbox', { name: 'Select row' })[1]);
    fireEvent.click(screen.getAllByRole('checkbox', { name: 'Select row' })[2]);
    expect(all.getAttribute('aria-checked')).toBe('true');
  });

  it('clears every row selection when the checked header checkbox is clicked', () => {
    const { container } = render(
      <DataTable columns={[createSelectColumn<Item>(), ...nameColumns]} data={items(2)} />
    );

    const all = screen.getByRole('checkbox', { name: 'Select all' });
    fireEvent.click(all);
    fireEvent.click(all);

    for (const box of screen.getAllByRole('checkbox', { name: 'Select row' })) {
      expect(box.getAttribute('aria-checked')).toBe('false');
    }
    expect(container.textContent).toContain('Showing 1 to 2 of 2 results');
  });
});
