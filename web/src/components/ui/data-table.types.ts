/**
 * Type definitions for DataTable component suite
 */

import { ColumnDef } from "@tanstack/react-table"

/**
 * Filter column configuration for faceted filters
 */
export interface FilterColumn {
  id: string
  title: string
  options: FilterOption[]
}

/**
 * Filter option for faceted filters
 */
export interface FilterOption {
  label: string
  value: string
  icon?: React.ComponentType<{ className?: string }>
}

/**
 * Bulk action configuration
 */
export interface BulkAction<TData> {
  label: string
  onClick: (rows: TData[]) => void
  variant?: "default" | "destructive"
  icon?: React.ComponentType<{ className?: string }>
}

/**
 * Row action configuration
 */
export interface RowAction<TData> {
  label: string
  onClick: (row: TData) => void
  variant?: "default" | "destructive"
  separator?: boolean
  icon?: React.ComponentType<{ className?: string }>
}

/**
 * DataTable configuration options
 */
export interface DataTableConfig<TData, TValue = unknown> {
  columns: ColumnDef<TData, TValue>[]
  data: TData[]
  searchKey?: string
  searchPlaceholder?: string
  filterableColumns?: FilterColumn[]
  pagination?: boolean
  pageSize?: number
  pageSizeOptions?: number[]
  onRowClick?: (row: TData) => void
  bulkActions?: BulkAction<TData>[]
  loading?: boolean
  emptyState?: React.ReactNode
  className?: string
}

/**
 * Column header sort state
 */
export type SortDirection = "asc" | "desc" | false

/**
 * Table loading state
 */
export type LoadingState = "idle" | "loading" | "error" | "success"

/**
 * Empty state configuration
 */
export interface EmptyStateConfig {
  title: string
  description?: string
  icon?: React.ComponentType<{ className?: string }>
  action?: {
    label: string
    onClick: () => void
  }
}

/**
 * Pagination state
 */
export interface PaginationState {
  pageIndex: number
  pageSize: number
  pageCount: number
  totalRows: number
}

/**
 * Filter state
 */
export interface FilterState {
  columnId: string
  value: unknown
}

/**
 * Selection state
 */
export interface SelectionState<TData> {
  selectedRows: TData[]
  selectedRowIds: Set<string>
  isAllSelected: boolean
  isSomeSelected: boolean
}

/**
 * Helper type for creating typed columns
 */
export type TypedColumnDef<TData, TValue = unknown> = ColumnDef<TData, TValue>

/**
 * Helper type for creating typed filters
 */
export type TypedFilterColumn<TData> = {
  id: keyof TData & string
  title: string
  options: FilterOption[]
}

/**
 * Helper type for creating typed bulk actions
 */
export type TypedBulkAction<TData> = BulkAction<TData>

/**
 * Helper type for creating typed row actions
 */
export type TypedRowAction<TData> = RowAction<TData>
