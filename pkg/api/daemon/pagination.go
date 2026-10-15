// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package daemon

import (
	"sort"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// pageOrder maps each sort_by value a list RPC accepts onto the order it
// sorts by. The "" key is the order used when sort_by is unset.
type pageOrder[T any] map[string]func(a, b T) bool

// sortPage orders items stably by the request's sort_by field. An unset
// sort_by sorts ascending by the "" order; a set one sorts in the direction
// the request's ascending flag names. It reports false, and leaves items
// unsorted, when sort_by names no order in orders.
func sortPage[T any](items []T, pagination *platformv1.PaginationRequest, orders pageOrder[T]) bool {
	sortBy := pagination.GetSortBy()
	less, ok := orders[sortBy]
	if !ok {
		return false
	}
	ascending := sortBy == "" || pagination.GetAscending()

	sort.SliceStable(items, func(i, j int) bool {
		if ascending {
			return less(items[i], items[j])
		}
		return less(items[j], items[i])
	})
	return true
}

// paginatePage slices a sorted result set according to the request's page and
// page_size. A zero page_size returns every item as a single page; a zero page
// means page 1; a page past the end returns no items. The response always
// reports the total item count so a caller can walk the remaining pages.
func paginatePage[T any](items []T, pagination *platformv1.PaginationRequest) ([]T, *platformv1.PaginationResponse) {
	total := uint64(len(items))
	pageSize := pagination.GetPageSize()
	if pageSize == 0 {
		return items, &platformv1.PaginationResponse{
			Page:       1,
			PageSize:   uint32(len(items)),
			TotalPages: 1,
			TotalItems: total,
		}
	}

	page := pagination.GetPage()
	if page == 0 {
		page = 1
	}
	response := &platformv1.PaginationResponse{
		Page:       page,
		PageSize:   pageSize,
		TotalPages: uint32((total + uint64(pageSize) - 1) / uint64(pageSize)),
		TotalItems: total,
	}

	start := uint64(page-1) * uint64(pageSize)
	if start >= total {
		return nil, response
	}
	end := min(start+uint64(pageSize), total)
	return items[start:end], response
}
