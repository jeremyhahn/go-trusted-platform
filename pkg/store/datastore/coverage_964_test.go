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

package datastore

import (
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/stretchr/testify/assert"
)

func TestStoreType_String(t *testing.T) {
	tests := []struct {
		name string
		in   StoreType
		want string
	}{
		{name: "named store", in: StoreType("raft"), want: "raft"},
		{name: "empty store", in: StoreType(""), want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.in.String())
		})
	}
}

// Only ConsistencyLevelQuorum reads as "quorum"; every other value,
// including an out-of-range one, falls back to "local".
func TestConsistencyLevel_String(t *testing.T) {
	tests := []struct {
		name string
		in   ConsistencyLevel
		want string
	}{
		{name: "local", in: ConsistencyLevelLocal, want: "local"},
		{name: "quorum", in: ConsistencyLevelQuorum, want: "quorum"},
		{name: "unknown falls back to local", in: ConsistencyLevel(99), want: "local"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.in.String())
		})
	}
}

func TestNewPageQuery_Defaults(t *testing.T) {
	q := NewPageQuery()

	assert.Equal(t, 1, q.Page)
	assert.Equal(t, 25, q.PageSize)
	assert.Equal(t, SortAscending, q.SortOrder)
}

// An empty result carries a non-nil entity slice, so it serialises as []
// rather than null.
func TestNewPageResult_EmptyNonNil(t *testing.T) {
	r := NewPageResult[entities.Blob]()

	assert.NotNil(t, r.Entities)
	assert.Empty(t, r.Entities)
	assert.Zero(t, r.Page)
	assert.Zero(t, r.PageSize)
	assert.False(t, r.HasMore)
}

func TestNewPageResultFromQuery(t *testing.T) {
	tests := []struct {
		name  string
		query PageQuery
	}{
		{name: "default query", query: NewPageQuery()},
		{name: "custom page", query: PageQuery{Page: 3, PageSize: 10, SortOrder: SortDescending}},
		{name: "zero page size", query: PageQuery{Page: 1, PageSize: 0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewPageResultFromQuery[entities.Blob](tt.query)

			assert.Equal(t, tt.query.Page, r.Page)
			assert.Equal(t, tt.query.PageSize, r.PageSize)
			assert.NotNil(t, r.Entities)
			assert.Empty(t, r.Entities)
			assert.Equal(t, tt.query.PageSize, cap(r.Entities))
		})
	}
}

func TestErrTrailingData_Error(t *testing.T) {
	var err error = ErrTrailingData{}

	assert.Equal(t, "trailing data after the entity's JSON document", err.Error())
}
