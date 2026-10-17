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

	"github.com/stretchr/testify/assert"
)

func TestPageQueryNormalizedKeepsValidQuery(t *testing.T) {
	query := PageQuery{Page: 3, PageSize: 7, SortOrder: SortDescending}
	assert.Equal(t, query, query.Normalized())
}

func TestPageQueryNormalizedFixesInvalidPaging(t *testing.T) {
	tests := []struct {
		name  string
		query PageQuery
		want  PageQuery
	}{
		{"zero value", PageQuery{}, PageQuery{Page: FirstPage, PageSize: DefaultPageSize}},
		{"zero page keeps size", PageQuery{PageSize: 100}, PageQuery{Page: FirstPage, PageSize: 100}},
		{"negative page and size", PageQuery{Page: -4, PageSize: -1}, PageQuery{Page: FirstPage, PageSize: DefaultPageSize}},
		{"sort order kept", PageQuery{SortOrder: SortDescending}, PageQuery{Page: FirstPage, PageSize: DefaultPageSize, SortOrder: SortDescending}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.query.Normalized())
		})
	}
}
