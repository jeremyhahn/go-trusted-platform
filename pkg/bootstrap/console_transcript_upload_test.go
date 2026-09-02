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
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// discardingSink counts the requests that reach it and lets each test
// decide what the nth one does. It is a real HTTP server, not a double:
// the behaviour under test is what net/http does to a PUT when the far
// side goes away, which only a real connection exhibits.
type discardingSink struct {
	mu       sync.Mutex
	requests int
	handle   func(n int, w http.ResponseWriter, r *http.Request)
}

func (s *discardingSink) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.requests++
	n := s.requests
	s.mu.Unlock()
	io.Copy(io.Discard, r.Body)
	s.handle(n, w, r)
}

func (s *discardingSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests
}

// dropConnection takes the connection away from net/http and closes it
// without answering — what a router that has aged the flow out of its
// connection table, or a sink that has been restarted under the
// orchestrator, looks like from the client side. The whole request body
// has already been read, so the client has certainly finished writing.
func dropConnection(t *testing.T, w http.ResponseWriter) {
	t.Helper()
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		t.Fatal("test server does not support hijacking")
	}
	conn, _, err := hijacker.Hijack()
	if err != nil {
		t.Fatalf("hijack: %v", err)
	}
	conn.Close()
}

func uploadTestOrchestrator(logs io.Writer) *Orchestrator {
	return &Orchestrator{
		logger:             slog.New(slog.NewTextHandler(logs, nil)),
		forensicRetryDelay: time.Millisecond,
	}
}

// A transcript upload must survive a connection the peer discards.
//
// This is the defect in #136: net/http will not re-dial for a PUT once
// any request byte is on the wire (Request.isReplayable excludes PUT),
// so the single attempt the upload used to get was spent on a dead
// connection and the artifact was lost. Delete the retry loop in
// uploadForensic and this test fails.
func TestUploadForensic_SurvivesAConnectionThePeerDiscards(t *testing.T) {
	sink := &discardingSink{handle: func(n int, w http.ResponseWriter, _ *http.Request) {
		if n == 1 {
			dropConnection(t, w)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}}
	srv := httptest.NewServer(sink)
	t.Cleanup(srv.Close)

	o := uploadTestOrchestrator(io.Discard)
	got, err := o.uploadForensic(t.Context(), srv.URL, "lab-node-5", "console-attempt1.log", []byte("boot\n"), "text/plain")
	if err != nil {
		t.Fatalf("upload must survive one discarded connection: %v", err)
	}
	if want := srv.URL + "/installs/lab-node-5/console-attempt1.log"; got != want {
		t.Errorf("URL = %q, want %q", got, want)
	}
	if sink.count() != 2 {
		t.Errorf("requests = %d, want 2 (one discarded, one served)", sink.count())
	}
}

// A sink that answers with a status has spoken; a second identical PUT
// would get the same answer, so the upload must not spend the rest of
// its budget asking again.
func TestUploadForensic_DoesNotRetryAStatusResponse(t *testing.T) {
	sink := &discardingSink{handle: func(_ int, w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInsufficientStorage)
	}}
	srv := httptest.NewServer(sink)
	t.Cleanup(srv.Close)

	o := uploadTestOrchestrator(io.Discard)
	if _, err := o.uploadForensic(t.Context(), srv.URL, "lab-node-5", "c.log", []byte("x"), "text/plain"); err == nil {
		t.Fatal("a non-2xx status must be an error")
	}
	if sink.count() != 1 {
		t.Errorf("requests = %d, want 1 — a status answer is not retried", sink.count())
	}
}

// When every attempt is spent, the warning must name the phase the
// attempt stalled in and the size it was carrying. Without that a run
// reports only "context deadline exceeded", which is what left #136
// undiagnosable through two fixes.
func TestUploadForensic_ExhaustsAttemptsAndNamesTheStalledPhase(t *testing.T) {
	sink := &discardingSink{handle: func(_ int, w http.ResponseWriter, _ *http.Request) {
		dropConnection(t, w)
	}}
	srv := httptest.NewServer(sink)
	t.Cleanup(srv.Close)

	var logs bytes.Buffer
	o := uploadTestOrchestrator(&logs)
	payload := bytes.Repeat([]byte("a"), 4096)
	if _, err := o.uploadForensic(t.Context(), srv.URL, "lab-node-5", "c.log", payload, "text/plain"); err == nil {
		t.Fatal("an upload that never lands must be an error")
	}
	if sink.count() != forensicUploadAttempts {
		t.Errorf("requests = %d, want %d", sink.count(), forensicUploadAttempts)
	}
	out := logs.String()
	if !strings.Contains(out, "stalled_in=") {
		t.Errorf("the warning must name the phase that stalled: %s", out)
	}
	if !strings.Contains(out, "awaiting response after sending the whole body") {
		t.Errorf("a discarded connection stalls awaiting the response: %s", out)
	}
	if !strings.Contains(out, "bytes=4096") {
		t.Errorf("the warning must report the size attempted: %s", out)
	}
}

// The budget bounds the whole upload. A cancelled context stops the
// retries rather than working through the remaining attempts.
func TestUploadForensic_StopsRetryingWhenTheBudgetEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	sink := &discardingSink{handle: func(_ int, w http.ResponseWriter, _ *http.Request) {
		cancel()
		dropConnection(t, w)
	}}
	srv := httptest.NewServer(sink)
	t.Cleanup(srv.Close)

	o := uploadTestOrchestrator(io.Discard)
	if _, err := o.uploadForensic(ctx, srv.URL, "lab-node-5", "c.log", []byte("x"), "text/plain"); err == nil {
		t.Fatal("a cancelled upload must be an error")
	}
	if sink.count() != 1 {
		t.Errorf("requests = %d, want 1 — cancellation stops the retries", sink.count())
	}
}

// The budget must actually cover every attempt and every pause between
// them; a budget shorter than the attempts it funds would cancel the
// upload mid-retry and reintroduce the bare "context deadline exceeded"
// #136 reported.
func TestForensicUploadBudget_CoversEveryAttempt(t *testing.T) {
	want := forensicUploadAttempts*forensicUploadTimeout + (forensicUploadAttempts-1)*forensicUploadRetryDelay
	if forensicUploadBudget != want {
		t.Errorf("budget = %s, want %s", forensicUploadBudget, want)
	}
	if forensicUploadBudget < forensicUploadAttempts*forensicUploadTimeout {
		t.Errorf("budget %s cannot fund %d attempts of %s", forensicUploadBudget, forensicUploadAttempts, forensicUploadTimeout)
	}
}
