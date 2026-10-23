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

package ovs

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testOwner uint64 = 0xF1BE000700000000

// sweepBridge is a bridge's flow table reduced to the cookies on it. Its
// stats query ignores the cookie filter, as a switch that matched loosely
// would, so the sweep's own owner check is what keeps other owners safe.
type sweepBridge struct {
	cookies   []uint64
	matches   []string
	deletes   []uint64
	statsErr  error
	deleteErr error
}

func (b *sweepBridge) GetFlowStats(_ context.Context, _ string, match string) ([]*Flow, error) {
	b.matches = append(b.matches, match)
	if b.statsErr != nil {
		return nil, b.statsErr
	}
	flows := make([]*Flow, 0, len(b.cookies))
	for _, c := range b.cookies {
		flows = append(flows, &Flow{Cookie: fmt.Sprintf("0x%x", c)})
	}
	return flows, nil
}

func (b *sweepBridge) DeleteFlowsByCookie(_ context.Context, _ string, cookie, mask uint64) error {
	if b.deleteErr != nil {
		return b.deleteErr
	}
	b.deletes = append(b.deletes, cookie)
	kept := b.cookies[:0]
	for _, c := range b.cookies {
		if c&mask != cookie&mask {
			kept = append(kept, c)
		}
	}
	b.cookies = kept
	return nil
}

func TestNewGenerationCookie_KeepsTheOwnerAndVaries(t *testing.T) {
	seen := map[uint64]bool{}
	for i := 0; i < 64; i++ {
		cookie, err := NewGenerationCookie(testOwner)
		require.NoError(t, err)
		assert.Equal(t, testOwner, cookie&OwnerCookieMask, "the owner id is in the high 32 bits")
		assert.NotZero(t, cookie&^OwnerCookieMask, "the generation is never zero")
		assert.False(t, seen[cookie], "generations must not repeat")
		seen[cookie] = true
	}
}

func TestNewGenerationCookie_RefusesAnOwnerWithoutRoomForAGeneration(t *testing.T) {
	for _, owner := range []uint64{0, testOwner | 1, 0x00000000FFFFFFFF} {
		t.Run(fmt.Sprintf("0x%x", owner), func(t *testing.T) {
			_, err := NewGenerationCookie(owner)
			var typed *ErrInvalidOwnerCookie
			require.ErrorAs(t, err, &typed)
			assert.Equal(t, owner, typed.Owner)
			assert.Contains(t, typed.Error(), "invalid owner cookie")
		})
	}
}

func TestSweepStaleGenerations_DeletesOnlyOlderGenerationsOfTheOwner(t *testing.T) {
	current := testOwner | 0x2
	stale := testOwner | 0x1
	other := uint64(0xF1BE000800000001)
	bridge := &sweepBridge{cookies: []uint64{stale, current, other, stale, 0}}

	require.NoError(t, SweepStaleGenerations(context.Background(), bridge, "br0", current))

	assert.Equal(t, []string{"cookie=0xf1be000700000000/0xffffffff00000000"}, bridge.matches,
		"the query is scoped to the owner")
	assert.Equal(t, []uint64{stale}, bridge.deletes, "each stale cookie is deleted once, exactly")
	assert.ElementsMatch(t, []uint64{current, other, 0}, bridge.cookies,
		"the current generation, another owner and cookie-less flows survive")
}

func TestSweepStaleGenerations_NothingStaleDeletesNothing(t *testing.T) {
	current := testOwner | 0x2
	bridge := &sweepBridge{cookies: []uint64{current}}
	require.NoError(t, SweepStaleGenerations(context.Background(), bridge, "br0", current))
	assert.Empty(t, bridge.deletes)
}

func TestSweepStaleGenerations_Errors(t *testing.T) {
	current := testOwner | 0x2
	boom := errors.New("boom")

	t.Run("stats", func(t *testing.T) {
		bridge := &sweepBridge{statsErr: boom}
		assert.ErrorIs(t, SweepStaleGenerations(context.Background(), bridge, "br0", current), boom)
	})
	t.Run("delete", func(t *testing.T) {
		bridge := &sweepBridge{cookies: []uint64{testOwner | 0x1}, deleteErr: boom}
		assert.ErrorIs(t, SweepStaleGenerations(context.Background(), bridge, "br0", current), boom)
	})
	t.Run("no owner", func(t *testing.T) {
		bridge := &sweepBridge{cookies: []uint64{0x5}}
		var typed *ErrInvalidOwnerCookie
		require.ErrorAs(t, SweepStaleGenerations(context.Background(), bridge, "br0", 0x5), &typed)
		assert.Empty(t, bridge.matches, "nothing is queried, let alone deleted, without an owner")
	})
}
