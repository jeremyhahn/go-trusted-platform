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

package bootstrap

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseInstallLogExitCode(t *testing.T) {
	cases := []struct {
		name string
		body string
		want int
	}{
		{"no manifest", "just a log line\nanother\n", 0},
		{"clean zero", "=== POSTMORTEM MANIFEST ===\nexit_code: 0\n", 0},
		{"non-zero", "=== POSTMORTEM MANIFEST ===\nexit_code: 42\nhostname: node-02\n", 42},
		{"negative", "exit_code: -1\n", -1},
		{"malformed not-a-number falls back to zero", "exit_code: oops\n", 0},
		{"whitespace around digits", "   exit_code:   7   \n", 7},
		{"multiple matches: last wins", "exit_code: 3\n... retry ...\nexit_code: 0\n", 0},
		{"embedded in postmortem block", "=== POSTMORTEM MANIFEST ===\nexit_code: 99\ntimestamp: 2026-04-08\n=== END POSTMORTEM ===\n", 99},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseInstallLogExitCode(tc.body); got != tc.want {
				t.Errorf("parseInstallLogExitCode(%q) = %d, want %d", tc.body, got, tc.want)
			}
		})
	}
}

func TestInstallLogResultSuccess(t *testing.T) {
	if (&InstallLogResult{Found: true, ExitCode: 0}).Success() != true {
		t.Error("found+zero should be Success")
	}
	if (&InstallLogResult{Found: true, ExitCode: 1}).Success() != false {
		t.Error("found+nonzero should NOT be Success")
	}
	if (&InstallLogResult{Found: false, ExitCode: 0}).Success() != false {
		t.Error("not-found should NOT be Success even with zero exit")
	}
}

// TestInstallLogPollerWait_SuccessAfterRetries starts an HTTP test server
// that returns 404 for the first two requests and then serves a
// POSTMORTEM manifest with exit_code 0. The poller should retry and
// return Success once the log becomes available.
func TestInstallLogPollerWait_SuccessAfterRetries(t *testing.T) {
	var hits atomic.Int64
	body := "=== POSTMORTEM MANIFEST ===\nexit_code: 0\nhostname: node-02\n=== END POSTMORTEM ===\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/installs/node-02/install.log" {
			http.Error(w, "wrong path", http.StatusBadRequest)
			return
		}
		n := hits.Add(1)
		if n < 3 {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	p := &InstallLogPoller{
		BaseURL:  srv.URL,
		Hostname: "node-02",
		Interval: 20 * time.Millisecond,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := p.Wait(ctx)
	if err != nil {
		t.Fatalf("Wait returned error: %v", err)
	}
	if res == nil || !res.Found {
		t.Fatalf("result not found: %+v", res)
	}
	if !res.Success() {
		t.Errorf("expected Success(), got %+v", res)
	}
	if res.ExitCode != 0 {
		t.Errorf("exit code = %d, want 0", res.ExitCode)
	}
	if hits.Load() < 3 {
		t.Errorf("expected ≥3 hits, got %d", hits.Load())
	}
}

// TestInstallLogPollerWait_FailureExitCode is the installer-crashed
// path: log uploads successfully, but the postmortem manifest reports a
// non-zero exit code. Poller should still return Found=true so the
// orchestrator can surface the log, but Success() must be false.
func TestInstallLogPollerWait_FailureExitCode(t *testing.T) {
	body := "=== POSTMORTEM MANIFEST ===\nexit_code: 42\nhostname: node-02\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	p := &InstallLogPoller{BaseURL: srv.URL, Hostname: "node-02", Interval: 10 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	res, err := p.Wait(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Found || res.Success() {
		t.Errorf("want found=true, success=false; got %+v", res)
	}
	if res.ExitCode != 42 {
		t.Errorf("exit code = %d, want 42", res.ExitCode)
	}
}

// TestInstallLogPollerWait_ContextTimeout guarantees the poller respects
// context cancellation and returns ctx.Err() when no log ever shows up.
func TestInstallLogPollerWait_ContextTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	p := &InstallLogPoller{BaseURL: srv.URL, Hostname: "node-02", Interval: 5 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	res, err := p.Wait(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("want context.DeadlineExceeded, got %v", err)
	}
	if res == nil || res.Found {
		t.Errorf("want found=false, got %+v", res)
	}
}

// TestInstallLogPollerWait_IgnoresStaleLog verifies the Since freshness
// gate. A prior-run log is served first (Last-Modified in the past),
// the poller rejects it, then on a subsequent attempt a fresh log is
// served and the poller accepts it.
func TestInstallLogPollerWait_IgnoresStaleLog(t *testing.T) {
	staleTime := time.Now().Add(-1 * time.Hour)
	freshTime := time.Now().Add(1 * time.Second)
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		if n < 3 {
			// Serve a stale log for the first two probes.
			w.Header().Set("Last-Modified", staleTime.UTC().Format(http.TimeFormat))
			_, _ = w.Write([]byte("=== POSTMORTEM MANIFEST ===\nexit_code: 0\n"))
			return
		}
		// Then serve a fresh one.
		w.Header().Set("Last-Modified", freshTime.UTC().Format(http.TimeFormat))
		_, _ = w.Write([]byte("=== POSTMORTEM MANIFEST ===\nexit_code: 0\n"))
	}))
	t.Cleanup(srv.Close)

	p := &InstallLogPoller{
		BaseURL:  srv.URL,
		Hostname: "node-02",
		Since:    time.Now(), // reject anything older than now
		Interval: 5 * time.Millisecond,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	res, err := p.Wait(ctx)
	if err != nil {
		t.Fatalf("Wait returned error: %v", err)
	}
	if !res.Found {
		t.Fatalf("expected fresh log to be found, got %+v", res)
	}
	if hits.Load() < 3 {
		t.Errorf("expected at least 3 hits (2 stale + 1 fresh), got %d", hits.Load())
	}
}

// TestInstallLogPollerWait_SinceZeroAllowsAny verifies that a zero
// Since value (the legacy behavior) still accepts the first log it
// sees, regardless of Last-Modified.
func TestInstallLogPollerWait_SinceZeroAllowsAny(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Last-Modified", time.Now().Add(-24*time.Hour).UTC().Format(http.TimeFormat))
		_, _ = w.Write([]byte("=== POSTMORTEM MANIFEST ===\nexit_code: 0\n"))
	}))
	t.Cleanup(srv.Close)

	p := &InstallLogPoller{
		BaseURL:  srv.URL,
		Hostname: "node-02",
		Interval: 5 * time.Millisecond,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	res, err := p.Wait(ctx)
	if err != nil {
		t.Fatalf("Wait returned error: %v", err)
	}
	if !res.Found {
		t.Errorf("expected any log to be accepted when Since=0, got %+v", res)
	}
}

// TestInstallLogPollerWait_TransientTransportError ensures transport
// errors (e.g. container briefly unreachable) are treated as "keep
// polling", not fatal.
func TestInstallLogPollerWait_TransientTransportError(t *testing.T) {
	// Use a URL that's guaranteed to refuse connections: the localhost
	// port 1 is reserved and should refuse. The poller should keep
	// polling and eventually exit via context.
	p := &InstallLogPoller{
		BaseURL:  "http://127.0.0.1:1",
		Hostname: "node-02",
		Interval: 5 * time.Millisecond,
		HTTPClient: &http.Client{
			Timeout: 100 * time.Millisecond,
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := p.Wait(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("want context.DeadlineExceeded (after retries), got %v", err)
	}
}
