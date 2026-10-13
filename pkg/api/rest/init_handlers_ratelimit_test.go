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

package rest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/security/ratelimit"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util/peercred"
)

// newInitLimiter returns a limiter that allows burst attempts and, for the
// duration of a test, never refills.
func newInitLimiter(t *testing.T, burst int) ratelimit.Limiter {
	t.Helper()
	limiter, err := ratelimit.NewTokenBucketLimiter(ratelimit.LimitConfig{
		Rate:            1e-9,
		Burst:           burst,
		CleanupInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewTokenBucketLimiter: %v", err)
	}
	t.Cleanup(func() { _ = limiter.Close() })
	return limiter
}

// postInit sends POST /init straight to the handler with ctx as the request
// context, which is how a test stands in for the Unix socket's peer
// credentials.
func postInit(ctx context.Context, h *InitHandlers) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/init", strings.NewReader(`{"so_pin":"so"}`)).WithContext(ctx)
	rec := httptest.NewRecorder()
	h.Init(rec, req)
	return rec
}

func TestInit_RateLimitedAfterBurst(t *testing.T) {
	init := &fakeInitService{resp: &BarrierInitResponse{}}
	h := NewInitHandlers(InitHandlersConfig{
		State:       newFakeStateProvider(PlatformStateUninitialized),
		Init:        init,
		InitLimiter: newInitLimiter(t, 2),
	})
	for i := 0; i < 2; i++ {
		if rec := postInit(context.Background(), h); rec.Code != http.StatusOK {
			t.Fatalf("attempt %d: expected 200, got %d", i+1, rec.Code)
		}
	}
	rec := postInit(context.Background(), h)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt past the burst: expected 429, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), (&ErrInitRateLimited{}).Error()) {
		t.Errorf("429 body does not carry ErrInitRateLimited: %s", rec.Body.String())
	}
	if init.called.Load() != 2 {
		t.Errorf("a rate-limited attempt reached the service: called=%d", init.called.Load())
	}
}

// TestInit_RateLimitAppliesAfterInitialization covers the replay path: a
// guesser probing an initialized barrier is limited too.
func TestInit_RateLimitAppliesAfterInitialization(t *testing.T) {
	h := NewInitHandlers(InitHandlersConfig{
		State:       newFakeStateProvider(PlatformStateSealed),
		Init:        &replayingInitService{},
		InitLimiter: newInitLimiter(t, 1),
	})
	if rec := postInit(context.Background(), h); rec.Code != http.StatusConflict {
		t.Fatalf("first attempt: expected 409, got %d", rec.Code)
	}
	if rec := postInit(context.Background(), h); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second attempt: expected 429, got %d", rec.Code)
	}
}

// TestInit_RateLimitBucketsPerCaller keeps a guesser on loopback HTTP from
// exhausting the attempts of an operator on the Unix socket, and one Unix
// uid from exhausting another's.
func TestInit_RateLimitBucketsPerCaller(t *testing.T) {
	h := NewInitHandlers(InitHandlersConfig{
		State:       newFakeStateProvider(PlatformStateUninitialized),
		Init:        &fakeInitService{resp: &BarrierInitResponse{}},
		InitLimiter: newInitLimiter(t, 1),
	})
	operator := peercred.ContextWithUnixCredentials(context.Background(), peercred.UnixCredentials{UID: 0})
	other := peercred.ContextWithUnixCredentials(context.Background(), peercred.UnixCredentials{UID: 1000})

	if rec := postInit(context.Background(), h); rec.Code != http.StatusOK {
		t.Fatalf("loopback: expected 200, got %d", rec.Code)
	}
	if rec := postInit(context.Background(), h); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("loopback again: expected 429, got %d", rec.Code)
	}
	if rec := postInit(other, h); rec.Code != http.StatusOK {
		t.Fatalf("uid 1000: expected its own bucket, got %d", rec.Code)
	}
	if rec := postInit(operator, h); rec.Code != http.StatusOK {
		t.Fatalf("uid 0: expected its own bucket, got %d", rec.Code)
	}
	if rec := postInit(operator, h); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("uid 0 again: expected 429, got %d", rec.Code)
	}
}

func TestErrInitRateLimited_Error(t *testing.T) {
	if msg := (&ErrInitRateLimited{}).Error(); !strings.Contains(msg, "rate") {
		t.Errorf("unexpected message: %q", msg)
	}
}
