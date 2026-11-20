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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/objectstorage"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// memChallengeObjects is a map-backed object store for the challenge sweep.
// The embedded interface is nil, so an unexercised call panics.
type memChallengeObjects struct {
	objectstorage.Client

	mu         sync.Mutex
	objs       map[string][]byte
	pageSize   int
	listErr    error
	failDelete map[string]bool
}

func (m *memChallengeObjects) PutObject(_ context.Context, req *objectstorage.PutObjectRequest) (*objectstorage.PutObjectResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.objs[req.Key] = append([]byte(nil), req.Value...)
	return &objectstorage.PutObjectResponse{Key: req.Key}, nil
}

func (m *memChallengeObjects) GetObject(_ context.Context, req *objectstorage.GetObjectRequest) (*objectstorage.GetObjectResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.objs[req.Key]
	if !ok {
		return nil, fmt.Errorf("object %q not found", req.Key)
	}
	return &objectstorage.GetObjectResponse{Key: req.Key, Value: append([]byte(nil), v...)}, nil
}

func (m *memChallengeObjects) DeleteObject(_ context.Context, req *objectstorage.DeleteObjectRequest) (*objectstorage.DeleteObjectResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failDelete[req.Key] {
		return nil, fmt.Errorf("delete %q refused", req.Key)
	}
	if _, ok := m.objs[req.Key]; !ok {
		return &objectstorage.DeleteObjectResponse{Key: req.Key, Success: false}, nil
	}
	delete(m.objs, req.Key)
	return &objectstorage.DeleteObjectResponse{Key: req.Key, Success: true}, nil
}

func (m *memChallengeObjects) ListObjects(_ context.Context, req *objectstorage.ListObjectsRequest) (*objectstorage.ListObjectsResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.listErr != nil {
		return nil, m.listErr
	}
	keys := make([]string, 0, len(m.objs))
	for k := range m.objs {
		if strings.HasPrefix(k, req.Prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	size := m.pageSize
	if size <= 0 {
		size = 2
	}
	start := 0
	if req.Cursor != "" {
		n, err := strconv.Atoi(req.Cursor)
		if err != nil {
			return nil, err
		}
		start = n
	}
	if start > len(keys) {
		start = len(keys)
	}
	end := start + size
	if end > len(keys) {
		end = len(keys)
	}
	resp := &objectstorage.ListObjectsResponse{}
	for _, k := range keys[start:end] {
		resp.Objects = append(resp.Objects, &objectstorage.ObjectSummary{Key: k})
	}
	if end < len(keys) {
		resp.HasMore = true
		resp.NextCursor = strconv.Itoa(end)
	}
	return resp, nil
}

func (m *memChallengeObjects) keys() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.objs))
	for k := range m.objs {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (m *memChallengeObjects) has(key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.objs[key]
	return ok
}

func (m *memChallengeObjects) putRecord(t *testing.T, key string, expiresAt time.Time) {
	t.Helper()
	raw, err := json.Marshal(attestChallengeRecord{DeviceID: "d", ExpiresAt: expiresAt})
	require.NoError(t, err)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.objs[key] = raw
}

func sweepFixture(t *testing.T) (*DeviceGRPCService, *memChallengeObjects, *time.Time, *quoteFixture) {
	t.Helper()
	f := newQuoteFixture(t)
	store := &memChallengeObjects{objs: map[string][]byte{}}
	clock := new(time.Time)
	*clock = f.now
	svc := challengeService(t, f, clock, WithDeviceAttestChallengeStorage(store))
	return svc, store, clock, f
}

func TestAttestChallengeStore_Sweep(t *testing.T) {
	ctx := context.Background()

	t.Run("removes expired, keeps live", func(t *testing.T) {
		svc, store, clock, f := sweepFixture(t)
		cctx := tokenCallerContext("tenant-a")
		var old []*platformv1.IssueAttestationChallengeResponse
		for i := 0; i < 3; i++ {
			old = append(old, issueChallenge(t, cctx, svc, itoa(f.device.ID)))
		}
		*clock = clock.Add(attestChallengeTTL + time.Second)
		fresh := issueChallenge(t, cctx, svc, itoa(f.device.ID))

		removed, err := svc.challenges.sweep(ctx)
		require.NoError(t, err)
		assert.Equal(t, 3, removed)
		assert.Equal(t, []string{attestChallengeKey(fresh.GetChallengeId())}, store.keys())

		resp, err := svc.AttestDevice(cctx, &platformv1.AttestDeviceRequest{
			DeviceId:    itoa(f.device.ID),
			Evidence:    f.evidence(t, fresh.GetNonce(), goldenPCRs()),
			ChallengeId: fresh.GetChallengeId(),
		})
		require.NoError(t, err)
		assert.True(t, resp.GetVerified())

		_, err = svc.AttestDevice(cctx, &platformv1.AttestDeviceRequest{
			DeviceId:    itoa(f.device.ID),
			Evidence:    f.evidence(t, old[0].GetNonce(), goldenPCRs()),
			ChallengeId: old[0].GetChallengeId(),
		})
		requireChallengeCode(t, err, codes.FailedPrecondition)
	})

	t.Run("boundary keeps a challenge at exactly its expiry", func(t *testing.T) {
		svc, store, clock, f := sweepFixture(t)
		start := *clock
		ch := issueChallenge(t, tokenCallerContext("tenant-a"), svc, itoa(f.device.ID))
		key := attestChallengeKey(ch.GetChallengeId())

		*clock = start.Add(attestChallengeTTL)
		removed, err := svc.challenges.sweep(ctx)
		require.NoError(t, err)
		assert.Equal(t, 0, removed)
		assert.True(t, store.has(key))

		*clock = start.Add(attestChallengeTTL + time.Second)
		removed, err = svc.challenges.sweep(ctx)
		require.NoError(t, err)
		assert.Equal(t, 1, removed)
		assert.False(t, store.has(key))
	})

	t.Run("pages through every record", func(t *testing.T) {
		svc, store, clock, _ := sweepFixture(t)
		store.pageSize = 2
		for i := 0; i < 5; i++ {
			store.putRecord(t, attestChallengeKey(fmt.Sprintf("exp%d", i)), clock.Add(-time.Second))
		}
		removed, err := svc.challenges.sweep(ctx)
		require.NoError(t, err)
		assert.Equal(t, 5, removed)
		assert.Empty(t, store.keys())
	})

	t.Run("other keys are left alone", func(t *testing.T) {
		svc, store, clock, _ := sweepFixture(t)
		store.putRecord(t, "other/x.json", clock.Add(-time.Hour))
		store.putRecord(t, "attest-challenges-extra/x.json", clock.Add(-time.Hour))
		store.putRecord(t, attestChallengeKey("gone"), clock.Add(-time.Hour))
		removed, err := svc.challenges.sweep(ctx)
		require.NoError(t, err)
		assert.Equal(t, 1, removed)
		assert.True(t, store.has("other/x.json"))
		assert.True(t, store.has("attest-challenges-extra/x.json"))
	})

	t.Run("an undecodable record is kept", func(t *testing.T) {
		svc, store, clock, _ := sweepFixture(t)
		bad := attestChallengeKey("bad")
		store.mu.Lock()
		store.objs[bad] = []byte("not json")
		store.mu.Unlock()
		store.putRecord(t, attestChallengeKey("a"), clock.Add(-time.Second))
		store.putRecord(t, attestChallengeKey("b"), clock.Add(-time.Second))
		removed, err := svc.challenges.sweep(ctx)
		require.NoError(t, err)
		assert.Equal(t, 2, removed)
		assert.Equal(t, []string{bad}, store.keys())
	})

	t.Run("a failed delete does not stop the others", func(t *testing.T) {
		svc, store, clock, _ := sweepFixture(t)
		failed := attestChallengeKey("b")
		store.failDelete = map[string]bool{failed: true}
		for _, id := range []string{"a", "b", "c"} {
			store.putRecord(t, attestChallengeKey(id), clock.Add(-time.Second))
		}
		removed, err := svc.challenges.sweep(ctx)
		require.Error(t, err)
		assert.Equal(t, 2, removed)
		assert.Equal(t, []string{failed}, store.keys())
	})

	t.Run("a list error deletes nothing", func(t *testing.T) {
		svc, store, clock, _ := sweepFixture(t)
		store.putRecord(t, attestChallengeKey("a"), clock.Add(-time.Second))
		store.listErr = errors.New("list refused")
		removed, err := svc.challenges.sweep(ctx)
		require.Error(t, err)
		assert.Equal(t, 0, removed)
		assert.True(t, store.has(attestChallengeKey("a")))
	})
}

func TestAttestChallengeStore_SweepInMemory(t *testing.T) {
	f := newQuoteFixture(t)
	clock := f.now
	svc := challengeService(t, f, &clock)
	cctx := tokenCallerContext("tenant-a")
	issueChallenge(t, cctx, svc, itoa(f.device.ID))
	issueChallenge(t, cctx, svc, itoa(f.device.ID))
	clock = clock.Add(attestChallengeTTL + time.Second)

	removed, err := svc.challenges.sweep(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, removed)
	svc.challenges.mu.Lock()
	n := len(svc.challenges.entries)
	svc.challenges.mu.Unlock()
	assert.Equal(t, 0, n)

	live := issueChallenge(t, cctx, svc, itoa(f.device.ID))
	removed, err = svc.challenges.sweep(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, removed)
	svc.challenges.mu.Lock()
	_, ok := svc.challenges.entries[live.GetChallengeId()]
	svc.challenges.mu.Unlock()
	assert.True(t, ok)
}

func TestAttestChallengeSweeper_RunsOnTick(t *testing.T) {
	svc, _, clock, f := sweepFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ticks := make(chan time.Time)
	results := make(chan int, 4)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		svc.challenges.runSweeper(ctx, ticks, func(removed int, err error) { results <- removed })
	}()

	cctx := tokenCallerContext("tenant-a")
	issueChallenge(t, cctx, svc, itoa(f.device.ID))
	issueChallenge(t, cctx, svc, itoa(f.device.ID))
	// The sweeper goroutine reads the clock only while handling a tick, and
	// the unbuffered send orders this write before that read.
	*clock = clock.Add(attestChallengeTTL + time.Second)

	ticks <- *clock
	assert.Equal(t, 2, <-results)
	ticks <- *clock
	assert.Equal(t, 0, <-results)

	cancel()
	wg.Wait()
}

func TestAttestChallengeSweeper_StartStop(t *testing.T) {
	svc, _, _, _ := sweepFixture(t)
	sw := &svc.challenges.sweeper

	svc.StartChallengeSweeper(time.Hour)
	svc.StartChallengeSweeper(time.Hour)
	sw.mu.Lock()
	assert.NotNil(t, sw.cancel)
	assert.Equal(t, 1, sw.started)
	sw.mu.Unlock()

	svc.StopChallengeSweeper()
	sw.mu.Lock()
	assert.Nil(t, sw.cancel)
	sw.mu.Unlock()
	svc.StopChallengeSweeper()

	svc.StartChallengeSweeper(0)
	sw.mu.Lock()
	assert.NotNil(t, sw.cancel)
	assert.Equal(t, 2, sw.started)
	sw.mu.Unlock()
	svc.StopChallengeSweeper()
}
