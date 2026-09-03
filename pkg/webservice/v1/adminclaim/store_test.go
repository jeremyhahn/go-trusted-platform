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

package adminclaim

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecretStore_IssueAndRedeem(t *testing.T) {
	store := newSecretStore(time.Minute)

	secret, expiresAt, err := store.issue("carried")
	require.NoError(t, err)
	assert.NotEmpty(t, secret)
	assert.True(t, expiresAt.After(time.Now()))

	value, ok := store.peek(secret)
	require.True(t, ok, "peek must not consume")
	assert.Equal(t, "carried", value)

	value, ok = store.redeem(secret)
	require.True(t, ok)
	assert.Equal(t, "carried", value)

	_, ok = store.redeem(secret)
	assert.False(t, ok, "redemption is single use")
	_, ok = store.peek(secret)
	assert.False(t, ok)
}

func TestSecretStore_RejectsUnknownAndEmpty(t *testing.T) {
	store := newSecretStore(time.Minute)
	for _, secret := range []string{"", "never-issued"} {
		_, ok := store.redeem(secret)
		assert.False(t, ok)
		_, ok = store.peek(secret)
		assert.False(t, ok)
	}
}

func TestSecretStore_Expiry(t *testing.T) {
	store := newSecretStore(time.Minute)
	now := time.Now()
	store.now = func() time.Time { return now }

	secret, _, err := store.issue("v")
	require.NoError(t, err)

	// Advance past the TTL without sleeping.
	now = now.Add(2 * time.Minute)
	_, ok := store.peek(secret)
	assert.False(t, ok, "an expired secret must not peek")
	_, ok = store.redeem(secret)
	assert.False(t, ok, "an expired secret must not redeem")
}

// TestSecretStore_SweepReclaimsCapacity proves an abandoned burst of
// challenges cannot hold the store at its cap until process exit.
func TestSecretStore_SweepReclaimsCapacity(t *testing.T) {
	store := newSecretStore(time.Minute)
	now := time.Now()
	store.now = func() time.Time { return now }

	for i := 0; i < maxOutstanding; i++ {
		_, _, err := store.issue("v")
		require.NoError(t, err)
	}
	_, _, err := store.issue("v")
	var full ErrTooManyOutstanding
	require.ErrorAs(t, err, &full)
	assert.Equal(t, maxOutstanding, full.Limit)

	now = now.Add(2 * time.Minute)
	_, _, err = store.issue("v")
	require.NoError(t, err, "expired entries must free capacity")
}

// TestSecretStore_RedemptionHasExactlyOneWinner is the concurrency claim
// the design rests on: a leaked secret cannot be spent twice, however
// many callers race for it.
func TestSecretStore_RedemptionHasExactlyOneWinner(t *testing.T) {
	store := newSecretStore(time.Minute)
	secret, _, err := store.issue("v")
	require.NoError(t, err)

	const racers = 32
	var wg sync.WaitGroup
	results := make(chan bool, racers)
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, ok := store.redeem(secret)
			results <- ok
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	winners := 0
	for ok := range results {
		if ok {
			winners++
		}
	}
	assert.Equal(t, 1, winners)
}

// TestSecretStore_CapHoldsUnderConcurrentIssue is the memory-exhaustion
// guard's real claim. These endpoints are reachable pre-auth, so a burst
// of concurrent callers must not all slip past the cap between a check and
// an increment. It counts the STORED entries, not the counter, because the
// counter is what a buggy implementation would get right.
func TestSecretStore_CapHoldsUnderConcurrentIssue(t *testing.T) {
	store := newSecretStore(time.Minute)

	const racers = maxOutstanding * 4
	var wg sync.WaitGroup
	var issued atomic.Int64
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, _, err := store.issue("v"); err == nil {
				issued.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	stored := 0
	store.entries.Range(func(_, _ any) bool {
		stored++
		return true
	})

	assert.LessOrEqual(t, stored, maxOutstanding,
		"the store must never hold more than the cap")
	assert.Equal(t, maxOutstanding, stored,
		"a full burst should fill the store exactly to the cap")
	assert.Equal(t, int64(stored), issued.Load(),
		"every success must correspond to a stored entry")
	assert.Equal(t, int64(stored), store.outstanding.Load(),
		"the counter must agree with the stored entries once the burst settles")
}
