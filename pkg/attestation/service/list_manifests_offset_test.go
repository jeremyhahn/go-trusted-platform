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

package service

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/store"
)

// pagedService is the real Service over a FileStore holding 25 manifests
// m-01..m-25, one minute apart; the listing is newest first.
func pagedService(t *testing.T) *Service {
	t.Helper()
	st, err := store.NewFileStore(t.TempDir())
	require.NoError(t, err)
	base := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	for i := 1; i <= 25; i++ {
		require.NoError(t, st.PutManifest(&manifest.HostManifest{
			ID:         fmt.Sprintf("m-%02d", i),
			HostID:     "host-a",
			Timestamp:  base.Add(time.Duration(i) * time.Minute),
			Nonce:      []byte{1},
			MerkleRoot: []byte{2},
		}))
	}
	return NewService(st)
}

// pageIDs returns the IDs at newest-first positions [from, to).
func pageIDs(from, to int) []string {
	ids := []string{}
	for pos := from; pos < to; pos++ {
		ids = append(ids, fmt.Sprintf("m-%02d", 25-pos))
	}
	return ids
}

func TestListManifests_PagesWithOffset(t *testing.T) {
	svc := pagedService(t)
	cases := []struct {
		name   string
		filter daemon.ListManifestsFilter
		want   []string
	}{
		{"limit 10 offset 10", daemon.ListManifestsFilter{Limit: 10, Offset: 10}, pageIDs(10, 20)},
		{"offset 20", daemon.ListManifestsFilter{Offset: 20}, pageIDs(20, 25)},
		{"offset 30", daemon.ListManifestsFilter{Offset: 30}, []string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, total, err := svc.ListManifests(context.Background(), &tc.filter)
			require.NoError(t, err)
			ids := []string{}
			for _, m := range got {
				ids = append(ids, m.ID)
			}
			assert.Equal(t, tc.want, ids)
			assert.Equal(t, 25, total, "total is the count before offset and limit")
		})
	}
}

func TestListManifests_NegativeOffsetIsTypedError(t *testing.T) {
	svc := pagedService(t)

	got, total, err := svc.ListManifests(context.Background(), &daemon.ListManifestsFilter{Offset: -5})

	var negErr *store.NegativeOffsetError
	require.ErrorAs(t, err, &negErr)
	assert.Equal(t, -5, negErr.Offset)
	assert.Nil(t, got)
	assert.Zero(t, total)
}
