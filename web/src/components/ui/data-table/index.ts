/**
 * DataTable Component Suite
 *
 * A comprehensive data table solution for the go-trusted-platform control panel
 * with sorting, filtering, pagination, and row selection.
 *
 * @see data-table.md for full documentation
 * @see data-table.example.tsx for usage examples
 * @see data-table.a11y.md for accessibility guidelines
 */

export { DataTable, createSelectColumn, type DataTableProps } from "../data-table"
export { DataTableColumnHeader } from "../data-table-column-header"
export { DataTablePagination } from "../data-table-pagination"
export { DataTableToolbar } from "../data-table-toolbar"
export { DataTableRowActions } from "../data-table-row-actions"
export { DataTableFacetedFilter } from "../data-table-faceted-filter"

/**
 * Quick Start Example:
 *
 * ```typescript
 * import { ColumnDef } from "@tanstack/react-table"
 * import {
 *   DataTable,
 *   createSelectColumn,
 *   DataTableColumnHeader,
 *   DataTableRowActions
 * } from "@/components/ui/data-table"
 *
 * const columns: ColumnDef<User>[] = [
 *   createSelectColumn<User>(),
 *   {
 *     accessorKey: "name",
 *     header: ({ column }) => (
 *       <DataTableColumnHeader column={column} title="Name" />
 *     ),
 *   },
 *   {
 *     id: "actions",
 *     cell: ({ row }) => (
 *       <DataTableRowActions
 *         row={row.original}
 *         actions={[
 *           { label: "Edit", onClick: editUser },
 *           { label: "Delete", onClick: deleteUser, variant: "destructive" },
 *         ]}
 *       />
 *     ),
 *   },
 * ]
 *
 * export function UsersTable() {
 *   return (
 *     <DataTable
 *       columns={columns}
 *       data={users}
 *       searchKey="name"
 *       searchPlaceholder="Search users..."
 *       filterableColumns={[
 *         {
 *           id: "status",
 *           title: "Status",
 *           options: [
 *             { label: "Active", value: "active" },
 *             { label: "Inactive", value: "inactive" },
 *           ],
 *         },
 *       ]}
 *       bulkActions={[
 *         { label: "Delete", onClick: deleteUsers, variant: "destructive" },
 *       ]}
 *       pagination
 *       pageSize={25}
 *     />
 *   )
 * }
 * ```
 */
