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

package controlplane

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
)

type stubFetcher struct {
	mu   sync.Mutex
	docs []*gwstate.DesiredConfig
	err  error
	n    int
}

func (f *stubFetcher) FetchDesiredConfig(context.Context) (*gwstate.DesiredConfig, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	if f.err != nil {
		return nil, f.err
	}
	doc := f.docs[0]
	if len(f.docs) > 1 {
		f.docs = f.docs[1:]
	}
	return doc, nil
}

type stubApplier struct {
	mu       sync.Mutex
	applied  []string
	err      error
	notify   chan struct{}
	lastSeen string
}

func (a *stubApplier) Apply(_ context.Context, d *gwstate.DesiredConfig) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.lastSeen = d.EffectiveVersion()
	if a.err != nil {
		return a.err
	}
	// The applier owns idempotence: an already-applied version is a no-op.
	if len(a.applied) > 0 && a.applied[len(a.applied)-1] == d.Version {
		return nil
	}
	a.applied = append(a.applied, d.Version)
	if a.notify != nil {
		select {
		case a.notify <- struct{}{}:
		default:
		}
	}
	return nil
}

func TestNewReconciler_RefusesIncompleteConfig(t *testing.T) {
	f := &stubFetcher{docs: []*gwstate.DesiredConfig{{}}}
	a := &stubApplier{}
	_, err := NewReconciler(ReconcilerConfig{Applier: a, Interval: time.Second})
	require.Error(t, err)
	_, err = NewReconciler(ReconcilerConfig{Fetcher: f, Interval: time.Second})
	require.Error(t, err)
	_, err = NewReconciler(ReconcilerConfig{Fetcher: f, Applier: a})
	var invalid *ErrConfigInvalid
	require.True(t, errors.As(err, &invalid), "got %v", err)
	r, err := NewReconciler(ReconcilerConfig{Fetcher: f, Applier: a, Interval: time.Second})
	require.NoError(t, err)
	require.NotNil(t, r)
}

func TestReconciler_ReconcileOnce(t *testing.T) {
	t.Run("applies a changed document and skips an unchanged one", func(t *testing.T) {
		f := &stubFetcher{docs: []*gwstate.DesiredConfig{{Version: "rev-1"}, {Version: "rev-1"}, {Version: "rev-2"}}}
		a := &stubApplier{}
		r, _ := NewReconciler(ReconcilerConfig{Fetcher: f, Applier: a, Interval: time.Second})
		for i := 0; i < 3; i++ {
			require.NoError(t, r.ReconcileOnce(context.Background()))
		}
		assert.Equal(t, []string{"rev-1", "rev-2"}, a.applied)
	})
	t.Run("fetch failure is typed", func(t *testing.T) {
		f := &stubFetcher{err: errors.New("cp unreachable")}
		a := &stubApplier{}
		r, _ := NewReconciler(ReconcilerConfig{Fetcher: f, Applier: a, Interval: time.Second})
		err := r.ReconcileOnce(context.Background())
		var failed *ErrReconcileFailed
		require.True(t, errors.As(err, &failed), "got %v", err)
		assert.Equal(t, "fetch", failed.Stage)
		assert.Empty(t, a.applied)
	})
	t.Run("apply failure is typed and reported", func(t *testing.T) {
		f := &stubFetcher{docs: []*gwstate.DesiredConfig{{Version: "rev-1"}}}
		a := &stubApplier{err: errors.New("nat not active")}
		r, _ := NewReconciler(ReconcilerConfig{Fetcher: f, Applier: a, Interval: time.Second})
		err := r.ReconcileOnce(context.Background())
		var failed *ErrReconcileFailed
		require.True(t, errors.As(err, &failed), "got %v", err)
		assert.Equal(t, "apply", failed.Stage)
		assert.ErrorContains(t, err, "nat not active")
	})
}

func TestReconciler_StartRunsImmediatelyThenOnTheTicker(t *testing.T) {
	notify := make(chan struct{}, 4)
	f := &stubFetcher{docs: []*gwstate.DesiredConfig{{Version: "rev-1"}, {Version: "rev-2"}}}
	a := &stubApplier{notify: notify}
	r, _ := NewReconciler(ReconcilerConfig{Fetcher: f, Applier: a, Interval: 20 * time.Millisecond})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Start(ctx) }()

	// First pass is immediate; the second document lands on a tick.
	for i := 0; i < 2; i++ {
		select {
		case <-notify:
		case <-time.After(5 * time.Second):
			t.Fatalf("apply %d did not happen", i+1)
		}
	}
	assert.Equal(t, ErrAlreadyRunning{}, r.Start(ctx))
	assert.NoError(t, r.LastError(), "clean passes leave no error behind")
	cancel()
	select {
	case err := <-done:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after cancel")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	assert.Equal(t, []string{"rev-1", "rev-2"}, a.applied)
}

func TestErrReconcileFailed_Unwrap(t *testing.T) {
	cause := errors.New("boom")
	err := &ErrReconcileFailed{Stage: "fetch", Cause: cause}
	assert.ErrorIs(t, err, cause)
	assert.Contains(t, err.Error(), "fetch")
}

func TestReconciler_StartRecordsAFailingPass(t *testing.T) {
	f := &stubFetcher{err: errors.New("cp unreachable")}
	a := &stubApplier{}
	r, _ := NewReconciler(ReconcilerConfig{Fetcher: f, Applier: a, Interval: 20 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Start(ctx) }()

	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	probe := time.NewTicker(5 * time.Millisecond)
	defer probe.Stop()
	for r.LastError() == nil {
		select {
		case <-deadline.C:
			t.Fatal("the failing pass was never recorded")
		case <-probe.C:
		}
	}
	var failed *ErrReconcileFailed
	assert.True(t, errors.As(r.LastError(), &failed))
	cancel()
	<-done
}
