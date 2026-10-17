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

package dns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewPage(t *testing.T) {
	tests := []struct {
		name          string
		n             int
		limit, offset int
		paged         bool
		want          Page
	}{
		{
			name: "unpaged covers the whole list and reports the resolved request",
			n:    120, limit: 2, offset: 7, paged: false,
			want: Page{Limit: 2, Offset: 7, Start: 0, End: 120},
		},
		{
			name: "a page inside the list",
			n:    10, limit: 3, offset: 4, paged: true,
			want: Page{Limit: 3, Offset: 4, Start: 4, End: 7},
		},
		{
			name: "the last page is short",
			n:    10, limit: 3, offset: 9, paged: true,
			want: Page{Limit: 3, Offset: 9, Start: 9, End: 10},
		},
		{
			name: "an offset past the end is an empty page",
			n:    10, limit: 3, offset: 40, paged: true,
			want: Page{Limit: 3, Offset: 40, Start: 10, End: 10},
		},
		{
			name: "an empty list is an empty page",
			n:    0, limit: 3, offset: 0, paged: true,
			want: Page{Limit: 3, Offset: 0, Start: 0, End: 0},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, NewPage(tt.n, tt.limit, tt.offset, tt.paged))
		})
	}
}

func TestNewPage_ClampsOutOfRangeRequests(t *testing.T) {
	tests := []struct {
		name          string
		limit, offset int
		want          Page
	}{
		{
			name:  "a zero limit is the default",
			limit: 0, offset: 0,
			want: Page{Limit: DefaultPageLimit, Offset: 0, Start: 0, End: DefaultPageLimit},
		},
		{
			name:  "a negative limit is the default",
			limit: -5, offset: 0,
			want: Page{Limit: DefaultPageLimit, Offset: 0, Start: 0, End: DefaultPageLimit},
		},
		{
			name:  "a limit above the cap is the cap",
			limit: MaxPageLimit + 1, offset: 0,
			want: Page{Limit: MaxPageLimit, Offset: 0, Start: 0, End: MaxPageLimit},
		},
		{
			name:  "a negative offset is zero",
			limit: 10, offset: -3,
			want: Page{Limit: 10, Offset: 0, Start: 0, End: 10},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, NewPage(2*MaxPageLimit, tt.limit, tt.offset, true))
		})
	}
}
