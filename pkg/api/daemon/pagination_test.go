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
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testStringOrders sorts strings by value or by length, length ties by value.
var testStringOrders = pageOrder[string]{
	"": func(a, b string) bool { return a < b },
	"length": func(a, b string) bool {
		if len(a) == len(b) {
			return a < b
		}
		return len(a) < len(b)
	},
}

func TestSortPage(t *testing.T) {
	tests := []struct {
		name       string
		pagination *platformv1.PaginationRequest
		want       []string
	}{
		{
			name: "no pagination sorts by the default order",
			want: []string{"a", "bb", "ccc", "dd"},
		},
		{
			name:       "unset sort_by ignores ascending=false",
			pagination: &platformv1.PaginationRequest{Ascending: false},
			want:       []string{"a", "bb", "ccc", "dd"},
		},
		{
			name:       "named field ascending",
			pagination: &platformv1.PaginationRequest{SortBy: "length", Ascending: true},
			want:       []string{"a", "bb", "dd", "ccc"},
		},
		{
			name:       "named field descending",
			pagination: &platformv1.PaginationRequest{SortBy: "length"},
			want:       []string{"ccc", "dd", "bb", "a"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			items := []string{"dd", "a", "ccc", "bb"}
			require.True(t, sortPage(items, tt.pagination, testStringOrders))
			assert.Equal(t, tt.want, items)
		})
	}
}

func TestSortPage_UnknownFieldLeavesItemsUnsorted(t *testing.T) {
	items := []string{"dd", "a", "ccc"}

	ok := sortPage(items, &platformv1.PaginationRequest{SortBy: "colour"}, testStringOrders)

	assert.False(t, ok)
	assert.Equal(t, []string{"dd", "a", "ccc"}, items)
}

func TestPaginatePage(t *testing.T) {
	items := []string{"a", "b", "c", "d", "e"}
	tests := []struct {
		name       string
		pagination *platformv1.PaginationRequest
		wantItems  []string
		wantPage   *platformv1.PaginationResponse
	}{
		{
			name:      "no pagination is one page of everything",
			wantItems: items,
			wantPage:  &platformv1.PaginationResponse{Page: 1, PageSize: 5, TotalPages: 1, TotalItems: 5},
		},
		{
			name:       "page zero is page one",
			pagination: &platformv1.PaginationRequest{PageSize: 2},
			wantItems:  []string{"a", "b"},
			wantPage:   &platformv1.PaginationResponse{Page: 1, PageSize: 2, TotalPages: 3, TotalItems: 5},
		},
		{
			name:       "middle page",
			pagination: &platformv1.PaginationRequest{Page: 2, PageSize: 2},
			wantItems:  []string{"c", "d"},
			wantPage:   &platformv1.PaginationResponse{Page: 2, PageSize: 2, TotalPages: 3, TotalItems: 5},
		},
		{
			name:       "last page is short",
			pagination: &platformv1.PaginationRequest{Page: 3, PageSize: 2},
			wantItems:  []string{"e"},
			wantPage:   &platformv1.PaginationResponse{Page: 3, PageSize: 2, TotalPages: 3, TotalItems: 5},
		},
		{
			name:       "page past the end is empty, not an error",
			pagination: &platformv1.PaginationRequest{Page: 4, PageSize: 2},
			wantItems:  nil,
			wantPage:   &platformv1.PaginationResponse{Page: 4, PageSize: 2, TotalPages: 3, TotalItems: 5},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, page := paginatePage(items, tt.pagination)
			assert.Equal(t, tt.wantItems, got)
			assert.Equal(t, tt.wantPage, page)
		})
	}
}

func TestPaginatePage_EmptySet(t *testing.T) {
	got, page := paginatePage([]string{}, &platformv1.PaginationRequest{Page: 1, PageSize: 10})

	assert.Empty(t, got)
	assert.Equal(t, &platformv1.PaginationResponse{Page: 1, PageSize: 10, TotalPages: 0, TotalItems: 0}, page)
}
