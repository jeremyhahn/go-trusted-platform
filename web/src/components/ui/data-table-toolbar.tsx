"use client"

import * as React from "react"
import { Table } from "@tanstack/react-table"
import { X } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { DataTableFacetedFilter } from "./data-table-faceted-filter"

interface DataTableToolbarProps<TData> {
  table: Table<TData>
  searchKey?: string
  searchPlaceholder?: string
  filterableColumns?: {
    id: string
    title: string
    options: { label: string; value: string }[]
  }[]
}

/**
 * Toolbar component for DataTable with search and filters
 *
 * Features:
 * - Global search input
 * - Column-specific faceted filters
 * - Clear all filters button
 * - Responsive layout
 *
 * Usage:
 * <DataTableToolbar
 *   table={table}
 *   searchKey="name"
 *   searchPlaceholder="Search names..."
 *   filterableColumns={[
 *     {
 *       id: "status",
 *       title: "Status",
 *       options: [
 *         { label: "Active", value: "active" },
 *         { label: "Inactive", value: "inactive" },
 *       ],
 *     },
 *   ]}
 * />
 */
export function DataTableToolbar<TData>({
  table,
  searchKey,
  searchPlaceholder = "Search...",
  filterableColumns = [],
}: DataTableToolbarProps<TData>) {
  const isFiltered = table.getState().columnFilters.length > 0

  return (
    <div className="flex items-center justify-between">
      <div className="flex flex-1 items-center space-x-2">
        {searchKey && (
          <Input
            placeholder={searchPlaceholder}
            value={(table.getColumn(searchKey)?.getFilterValue() as string) ?? ""}
            onChange={(event) =>
              table.getColumn(searchKey)?.setFilterValue(event.target.value)
            }
            className="h-8 w-[150px] lg:w-[250px]"
          />
        )}
        {filterableColumns.map((filterColumn) => {
          const column = table.getColumn(filterColumn.id)
          if (!column) return null

          return (
            <DataTableFacetedFilter
              key={filterColumn.id}
              column={column}
              title={filterColumn.title}
              options={filterColumn.options}
            />
          )
        })}
        {isFiltered && (
          <Button
            variant="ghost"
            onClick={() => table.resetColumnFilters()}
            className="h-8 px-2 lg:px-3"
          >
            Reset
            <X className="ml-2 h-4 w-4" />
          </Button>
        )}
      </div>
    </div>
  )
}
