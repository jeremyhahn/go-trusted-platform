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

package store

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

// pagedStore holds 25 manifests m-01..m-25, one minute apart, so the
// newest-first listing is m-25, m-24, ..., m-01.
func pagedStore(t *testing.T) *FileStore {
	t.Helper()
	s := newTestStore(t)
	base := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	for i := 1; i <= 25; i++ {
		m := testManifest(fmt.Sprintf("m-%02d", i), "host-1", base.Add(time.Duration(i)*time.Minute))
		if err := s.PutManifest(m); err != nil {
			t.Fatalf("PutManifest %d: %v", i, err)
		}
	}
	return s
}

// listingIDs returns the IDs at newest-first positions [from, to).
func listingIDs(from, to int) []string {
	ids := make([]string, 0, to-from)
	for pos := from; pos < to; pos++ {
		ids = append(ids, fmt.Sprintf("m-%02d", 25-pos))
	}
	return ids
}

func TestFileStore_ListManifests_Offset(t *testing.T) {
	s := pagedStore(t)
	cases := []struct {
		name   string
		filter ListFilter
		want   []string
	}{
		{"second page of ten", ListFilter{Limit: 10, Offset: 10}, listingIDs(10, 20)},
		{"offset twenty leaves five", ListFilter{Offset: 20}, listingIDs(20, 25)},
		{"offset at the end", ListFilter{Offset: 25}, []string{}},
		{"offset past the end", ListFilter{Offset: 30}, []string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, total, err := s.ListManifests(tc.filter)
			if err != nil {
				t.Fatalf("ListManifests: %v", err)
			}
			if total != 25 {
				t.Errorf("total = %d, want 25 (the count before offset and limit)", total)
			}
			if got == nil {
				t.Fatalf("page is nil, want an empty slice")
			}
			ids := make([]string, 0, len(got))
			for _, m := range got {
				ids = append(ids, m.ID)
			}
			if fmt.Sprint(ids) != fmt.Sprint(tc.want) {
				t.Errorf("ids = %v, want %v", ids, tc.want)
			}
		})
	}
}

func TestFileStore_ListManifests_NegativeOffset(t *testing.T) {
	s := pagedStore(t)
	got, total, err := s.ListManifests(ListFilter{Offset: -1})
	var negErr *NegativeOffsetError
	if !errors.As(err, &negErr) {
		t.Fatalf("err = %v, want *NegativeOffsetError", err)
	}
	if negErr.Offset != -1 {
		t.Errorf("Offset = %d, want -1", negErr.Offset)
	}
	if got != nil || total != 0 {
		t.Errorf("got %d manifests of %d, want none", len(got), total)
	}
}
