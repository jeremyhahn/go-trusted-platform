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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/barrier"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// =============================================================================
// Fakes
// =============================================================================

type fakeStateProvider struct {
	state atomic.Value // PlatformState
}

func newFakeStateProvider(s PlatformState) *fakeStateProvider {
	p := &fakeStateProvider{}
	p.state.Store(s)
	return p
}

func (p *fakeStateProvider) State(_ context.Context) PlatformState {
	v, _ := p.state.Load().(PlatformState)
	return v
}

type fakeInitService struct {
	called atomic.Int32
	resp   *BarrierInitResponse
	err    error
	last   *BarrierInitRequest
}

func (s *fakeInitService) Initialize(_ context.Context, req *BarrierInitRequest) (*BarrierInitResponse, error) {
	s.called.Add(1)
	s.last = req
	return s.resp, s.err
}

type fakeUnsealService struct {
	called atomic.Int32
	resp   *BarrierUnsealResponse
	err    error
	last   *BarrierUnsealRequest
}

func (s *fakeUnsealService) Unseal(_ context.Context, req *BarrierUnsealRequest) (*BarrierUnsealResponse, error) {
	s.called.Add(1)
	s.last = req
	return s.resp, s.err
}

// =============================================================================
// Test helpers
// =============================================================================

func newTestServer(state *fakeStateProvider, init BarrierInitService, unseal BarrierUnsealService) *httptest.Server {
	h := NewInitHandlers(InitHandlersConfig{
		State:  state,
		Init:   init,
		Unseal: unseal,
	})
	mux := http.NewServeMux()
	h.Register(mux)
	return httptest.NewServer(mux)
}

// =============================================================================
// /healthz
// =============================================================================

func TestHealthz_ReportsState(t *testing.T) {
	cases := []struct {
		name  string
		state PlatformState
		ready bool
	}{
		{"uninitialized", PlatformStateUninitialized, false},
		{"sealed", PlatformStateSealed, false},
		{"unsealing", PlatformStateUnsealing, false},
		{"unsealed", PlatformStateUnsealed, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := newTestServer(newFakeStateProvider(tc.state), nil, nil)
			t.Cleanup(ts.Close)
			resp, err := http.Get(ts.URL + "/healthz")
			if err != nil {
				t.Fatalf("GET /healthz: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("expected 200, got %d", resp.StatusCode)
			}
			var body BarrierHealthResponse
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if body.State != tc.state {
				t.Errorf("state: got %q want %q", body.State, tc.state)
			}
			if body.Ready != tc.ready {
				t.Errorf("ready: got %v want %v", body.Ready, tc.ready)
			}
		})
	}
}

func TestHealthz_RejectsNonGet(t *testing.T) {
	ts := newTestServer(newFakeStateProvider(PlatformStateUninitialized), nil, nil)
	t.Cleanup(ts.Close)
	resp, err := http.Post(ts.URL+"/healthz", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("POST /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

func TestHealthz_NilState(t *testing.T) {
	h := NewInitHandlers(InitHandlersConfig{})
	mux := http.NewServeMux()
	h.Register(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	var body BarrierHealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.State != PlatformStateUninitialized {
		t.Errorf("expected uninitialized, got %q", body.State)
	}
	if body.Ready {
		t.Error("expected not ready")
	}
}

// =============================================================================
// /init
// =============================================================================

func TestInit_Success(t *testing.T) {
	state := newFakeStateProvider(PlatformStateUninitialized)
	init := &fakeInitService{
		resp: &BarrierInitResponse{CeremonyID: "ceremony-1", SPKIPin: "sha256/pin"},
	}
	ts := newTestServer(state, init, nil)
	t.Cleanup(ts.Close)

	body := `{"so_pin":"sopin","user_pin":"userpin"}`
	resp, err := http.Post(ts.URL+"/init", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST /init: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if init.called.Load() != 1 {
		t.Errorf("init called %d times, want 1", init.called.Load())
	}
	if init.last == nil || init.last.SOPIN != "sopin" || init.last.UserPIN != "userpin" {
		t.Errorf("request not propagated: %+v", init.last)
	}
	var out BarrierInitResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.CeremonyID != "ceremony-1" {
		t.Errorf("ceremony id: got %q want ceremony-1", out.CeremonyID)
	}
	if out.SPKIPin != "sha256/pin" {
		t.Errorf("spki pin: got %q want sha256/pin", out.SPKIPin)
	}
	if out.State != PlatformStateUninitialized {
		t.Errorf("response state should reflect provider state, got %q", out.State)
	}
}

func TestInit_NotPermittedWhenInitialized(t *testing.T) {
	state := newFakeStateProvider(PlatformStateSealed)
	init := &fakeInitService{}
	ts := newTestServer(state, init, nil)
	t.Cleanup(ts.Close)

	resp, err := http.Post(ts.URL+"/init", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST /init: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409, got %d", resp.StatusCode)
	}
	if init.called.Load() != 0 {
		t.Errorf("init must not be called when already initialized")
	}
}

func TestInit_ServiceUnavailableWhenNoBackend(t *testing.T) {
	state := newFakeStateProvider(PlatformStateUninitialized)
	ts := newTestServer(state, nil, nil)
	t.Cleanup(ts.Close)

	resp, err := http.Post(ts.URL+"/init", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST /init: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", resp.StatusCode)
	}
}

func TestInit_BackendErrorBubblesUp(t *testing.T) {
	state := newFakeStateProvider(PlatformStateUninitialized)
	init := &fakeInitService{err: errors.New("boom")}
	ts := newTestServer(state, init, nil)
	t.Cleanup(ts.Close)

	resp, err := http.Post(ts.URL+"/init", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST /init: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", resp.StatusCode)
	}
}

func TestInit_RejectsNonPost(t *testing.T) {
	state := newFakeStateProvider(PlatformStateUninitialized)
	ts := newTestServer(state, &fakeInitService{}, nil)
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + "/init")
	if err != nil {
		t.Fatalf("GET /init: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

func TestInit_BadJSONReturns400(t *testing.T) {
	state := newFakeStateProvider(PlatformStateUninitialized)
	ts := newTestServer(state, &fakeInitService{}, nil)
	t.Cleanup(ts.Close)

	resp, err := http.Post(ts.URL+"/init", "application/json", strings.NewReader(`{not json`))
	if err != nil {
		t.Fatalf("POST /init: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

// postStatus posts body to path and returns the response status code.
func postStatus(t *testing.T, ts *httptest.Server, path, body string) int {
	t.Helper()
	resp, err := http.Post(ts.URL+path, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// TestInit_RejectsUnknownField proves a field the gate does not honour,
// such as the removed barrier_strategy, is refused rather than ignored.
func TestInit_RejectsUnknownField(t *testing.T) {
	init := &fakeInitService{}
	ts := newTestServer(newFakeStateProvider(PlatformStateUninitialized), init, nil)
	t.Cleanup(ts.Close)

	status := postStatus(t, ts, "/init", `{"user_pin":"p","barrier_strategy":"software"}`)
	if status != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", status)
	}
	if init.called.Load() != 0 {
		t.Error("init must not run for a refused body")
	}
}

func TestInit_ValidationErrorReturns400(t *testing.T) {
	cases := map[string]error{
		"missing field": ErrMissingRequiredField{Field: "user_pin"},
		"invalid body":  ErrInvalidRequestBody{Reason: "bad"},
		"wrapped":       &wrappedErr{cause: ErrMissingRequiredField{Field: "user_pin"}},
	}
	for name, svcErr := range cases {
		t.Run(name, func(t *testing.T) {
			ts := newTestServer(newFakeStateProvider(PlatformStateUninitialized), &fakeInitService{err: svcErr}, nil)
			t.Cleanup(ts.Close)
			if status := postStatus(t, ts, "/init", `{}`); status != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d", status)
			}
		})
	}
}

// wrappedErr wraps a cause the way a service error chain does.
type wrappedErr struct{ cause error }

func (e *wrappedErr) Error() string { return "wrapped: " + e.cause.Error() }
func (e *wrappedErr) Unwrap() error { return e.cause }

// =============================================================================
// /unseal
// =============================================================================

func TestUnseal_Success(t *testing.T) {
	state := newFakeStateProvider(PlatformStateSealed)
	unseal := &fakeUnsealService{
		resp: &BarrierUnsealResponse{Sealed: false, SharesProvided: 1, Required: 1},
	}
	ts := newTestServer(state, nil, unseal)
	t.Cleanup(ts.Close)

	resp, err := http.Post(ts.URL+"/unseal", "application/json",
		strings.NewReader(`{"secret":"key"}`))
	if err != nil {
		t.Fatalf("POST /unseal: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if unseal.called.Load() != 1 {
		t.Errorf("unseal called %d times, want 1", unseal.called.Load())
	}
	if unseal.last == nil || unseal.last.Secret != "key" {
		t.Errorf("secret not propagated: %+v", unseal.last)
	}
}

func TestUnseal_RejectsWhenUninitialized(t *testing.T) {
	state := newFakeStateProvider(PlatformStateUninitialized)
	ts := newTestServer(state, nil, &fakeUnsealService{})
	t.Cleanup(ts.Close)

	resp, err := http.Post(ts.URL+"/unseal", "application/json", strings.NewReader(`{"secret":"k"}`))
	if err != nil {
		t.Fatalf("POST /unseal: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409, got %d", resp.StatusCode)
	}
}

func TestUnseal_RejectsWhenAlreadyUnsealed(t *testing.T) {
	state := newFakeStateProvider(PlatformStateUnsealed)
	ts := newTestServer(state, nil, &fakeUnsealService{})
	t.Cleanup(ts.Close)

	resp, err := http.Post(ts.URL+"/unseal", "application/json", strings.NewReader(`{"secret":"k"}`))
	if err != nil {
		t.Fatalf("POST /unseal: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409, got %d", resp.StatusCode)
	}
}

func TestUnseal_AcceptsUnsealingState(t *testing.T) {
	state := newFakeStateProvider(PlatformStateUnsealing)
	unseal := &fakeUnsealService{
		resp: &BarrierUnsealResponse{Sealed: true, SharesProvided: 2, Required: 3},
	}
	ts := newTestServer(state, nil, unseal)
	t.Cleanup(ts.Close)

	resp, err := http.Post(ts.URL+"/unseal", "application/json",
		strings.NewReader(`{"share":"abcd"}`))
	if err != nil {
		t.Fatalf("POST /unseal: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if unseal.last == nil || unseal.last.Share != "abcd" {
		t.Errorf("share not propagated: %+v", unseal.last)
	}
}

func TestUnseal_ServiceUnavailableWhenNoBackend(t *testing.T) {
	state := newFakeStateProvider(PlatformStateSealed)
	ts := newTestServer(state, nil, nil)
	t.Cleanup(ts.Close)

	resp, err := http.Post(ts.URL+"/unseal", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST /unseal: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", resp.StatusCode)
	}
}

// TestUnseal_EmptyBodyReturns400 is the #823 regression: a body with
// neither secret nor share is a caller error, not a server fault.
func TestUnseal_EmptyBodyReturns400(t *testing.T) {
	unseal := &fakeUnsealService{err: ErrMissingRequiredField{Field: "secret or share"}}
	ts := newTestServer(newFakeStateProvider(PlatformStateSealed), nil, unseal)
	t.Cleanup(ts.Close)

	if status := postStatus(t, ts, "/unseal", `{}`); status != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", status)
	}
}

func TestUnseal_ServiceErrorReturns500(t *testing.T) {
	unseal := &fakeUnsealService{err: errors.New("wrong secret")}
	ts := newTestServer(newFakeStateProvider(PlatformStateSealed), nil, unseal)
	t.Cleanup(ts.Close)

	if status := postStatus(t, ts, "/unseal", `{"secret":"k"}`); status != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", status)
	}
}

// TestGate_BarrierErrorStatus is the #825 regression: a barrier or SDK error
// from the gate services answers the HTTP status of its barrier.Code, not a
// blanket 500.
func TestGate_BarrierErrorStatus(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"wrapped_not_sealed", &barrier.ManagerError{Op: "Unseal", Err: fmt.Errorf("upstream: %w", barrier.ErrNotSealed)}, http.StatusConflict},
		{"wrapped_already_initialized", fmt.Errorf("init: %w", barrier.ErrAlreadyInitialized), http.StatusConflict},
		{"wrapped_empty_share", fmt.Errorf("unseal: %w", barrier.ErrEmptyShare), http.StatusBadRequest},
		{"upstream_permission_denied", &barrier.ManagerError{Op: "Unseal", Err: status.Error(codes.PermissionDenied, "wrong secret")}, http.StatusForbidden},
		{"upstream_unavailable", &barrier.ManagerError{Op: "Unseal", Err: status.Error(codes.Unavailable, "no leader")}, http.StatusServiceUnavailable},
		{"unclassified", errors.New("disk on fire"), http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name+"/unseal", func(t *testing.T) {
			unseal := &fakeUnsealService{err: tt.err}
			ts := newTestServer(newFakeStateProvider(PlatformStateSealed), nil, unseal)
			t.Cleanup(ts.Close)

			if got := postStatus(t, ts, "/unseal", `{"secret":"k"}`); got != tt.want {
				t.Fatalf("expected %d, got %d", tt.want, got)
			}
		})
		t.Run(tt.name+"/init", func(t *testing.T) {
			initSvc := &fakeInitService{err: tt.err}
			ts := newTestServer(newFakeStateProvider(PlatformStateUninitialized), initSvc, nil)
			t.Cleanup(ts.Close)

			if got := postStatus(t, ts, "/init", `{"user_pin":"k"}`); got != tt.want {
				t.Fatalf("expected %d, got %d", tt.want, got)
			}
		})
	}
}

func TestUnseal_RejectsUnknownField(t *testing.T) {
	unseal := &fakeUnsealService{}
	ts := newTestServer(newFakeStateProvider(PlatformStateSealed), nil, unseal)
	t.Cleanup(ts.Close)

	if status := postStatus(t, ts, "/unseal", `{"secret":"k","passphrase":"x"}`); status != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", status)
	}
	if unseal.called.Load() != 0 {
		t.Error("unseal must not run for a refused body")
	}
}

// =============================================================================
// Errors
// =============================================================================

func TestErrInitNotPermitted_Error(t *testing.T) {
	e := &ErrInitNotPermitted{Current: PlatformStateSealed}
	if !strings.Contains(e.Error(), "sealed") {
		t.Errorf("error should include current state: %q", e.Error())
	}
}

func TestErrUnsealNotPermitted_Error(t *testing.T) {
	e := &ErrUnsealNotPermitted{Current: PlatformStateUninitialized}
	if !strings.Contains(e.Error(), "uninitialized") {
		t.Errorf("error should include current state: %q", e.Error())
	}
}

func TestErrBarrierInitServiceUnavailable_Error(t *testing.T) {
	e := &ErrBarrierInitServiceUnavailable{}
	if e.Error() == "" {
		t.Error("expected non-empty error string")
	}
}

func TestErrBarrierUnsealServiceUnavailable_Error(t *testing.T) {
	e := &ErrBarrierUnsealServiceUnavailable{}
	if e.Error() == "" {
		t.Error("expected non-empty error string")
	}
}

// =============================================================================
// MaxBodyBytes default
// =============================================================================

func TestNewInitHandlers_DefaultsMaxBody(t *testing.T) {
	h := NewInitHandlers(InitHandlersConfig{State: newFakeStateProvider(PlatformStateUninitialized)})
	if h.maxBody <= 0 {
		t.Errorf("expected positive default max body, got %d", h.maxBody)
	}
}

func TestNewInitHandlers_CustomMaxBody(t *testing.T) {
	h := NewInitHandlers(InitHandlersConfig{
		State:        newFakeStateProvider(PlatformStateUninitialized),
		MaxBodyBytes: 1024,
	})
	if h.maxBody != 1024 {
		t.Errorf("expected 1024, got %d", h.maxBody)
	}
}
