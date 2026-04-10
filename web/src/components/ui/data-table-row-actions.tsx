"use client"

import * as React from "react"
import { MoreHorizontal } from "lucide-react"

import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"

interface DataTableRowActionsProps<TData> {
  row: TData
  actions?: {
    label: string
    onClick: (row: TData) => void
    variant?: "default" | "destructive"
    separator?: boolean
  }[]
}

/**
 * Row actions dropdown component for DataTable
 *
 * Features:
 * - Three-dot menu for row-specific actions
 * - Support for destructive actions (e.g., Delete)
 * - Separators between action groups
 * - Accessible with keyboard navigation
 *
 * Usage in column definition:
 * {
 *   id: "actions",
 *   cell: ({ row }) => (
 *     <DataTableRowActions
 *       row={row.original}
 *       actions={[
 *         { label: "View", onClick: (row) => viewRow(row) },
 *         { label: "Edit", onClick: (row) => editRow(row) },
 *         { label: "Delete", onClick: (row) => deleteRow(row), variant: "destructive", separator: true },
 *       ]}
 *     />
 *   ),
 * }
 */
export function DataTableRowActions<TData>({
  row,
  actions = [],
}: DataTableRowActionsProps<TData>) {
  if (actions.length === 0) {
    return null
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="ghost"
          className="flex h-8 w-8 p-0 data-[state=open]:bg-muted"
        >
          <MoreHorizontal className="h-4 w-4" />
          <span className="sr-only">Open menu</span>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-[160px]">
        {actions.map((action, index) => (
          <React.Fragment key={index}>
            {action.separator && <DropdownMenuSeparator />}
            <DropdownMenuItem
              onClick={() => action.onClick(row)}
              className={
                action.variant === "destructive"
                  ? "text-destructive focus:text-destructive"
                  : ""
              }
            >
              {action.label}
            </DropdownMenuItem>
          </React.Fragment>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
