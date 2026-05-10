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

package commands

import (
	"context"
	"errors"
	"testing"

	apidaemon "github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
)

// =============================================================================
// barrierStateProvider
// =============================================================================

func TestBarrierStateProvider_NilApp(t *testing.T) {
	p := &barrierStateProvider{app: nil}
	if got := p.State(context.Background()); got != rest.PlatformStateUninitialized {
		t.Errorf("nil app: got %q want uninitialized", got)
	}
}

func TestBarrierStateProvider_NilProvider(t *testing.T) {
	var p *barrierStateProvider
	if got := p.State(context.Background()); got != rest.PlatformStateUninitialized {
		t.Errorf("nil provider: got %q want uninitialized", got)
	}
}

// =============================================================================
// formatThreshold / formatInt
// =============================================================================

func TestFormatThreshold(t *testing.T) {
	cases := []struct {
		t, n int
		want string
	}{
		{0, 0, ""},
		{2, 5, "2-of-5"},
		{1, 1, "1-of-1"},
		{3, 0, ""}, // shares missing
		{0, 5, ""}, // threshold missing
	}
	for _, tc := range cases {
		if got := formatThreshold(tc.t, tc.n); got != tc.want {
			t.Errorf("formatThreshold(%d,%d): got %q want %q", tc.t, tc.n, got, tc.want)
		}
	}
}

func TestFormatInt(t *testing.T) {
	cases := []struct {
		n    int
		want string
	}{
		{0, "0"},
		{5, "5"},
		{42, "42"},
		{-7, "-7"},
		{1234, "1234"},
	}
	for _, tc := range cases {
		if got := formatInt(tc.n); got != tc.want {
			t.Errorf("formatInt(%d): got %q want %q", tc.n, got, tc.want)
		}
	}
}

// =============================================================================
// barrierInitService
// =============================================================================

type fakeBackend struct {
	called int
	last   *apidaemon.CeremonyInitRequest
	resp   *apidaemon.CeremonyInitResult
	err    error
}

func (b *fakeBackend) Initialize(_ context.Context, req *apidaemon.CeremonyInitRequest) (*apidaemon.CeremonyInitResult, error) {
	b.called++
	b.last = req
	return b.resp, b.err
}
func (b *fakeBackend) Status(_ context.Context) (*apidaemon.CeremonyStatusInfo, error) {
	return nil, nil
}
func (b *fakeBackend) ClaimCertBegin(_ context.Context, _ *apidaemon.CeremonyClaimCertBeginRequest) (*apidaemon.CeremonyClaimCertBeginResult, error) {
	return nil, nil
}
func (b *fakeBackend) ClaimCertComplete(_ context.Context, _ *apidaemon.CeremonyClaimCertCompleteRequest) (*apidaemon.CeremonyClaimCertCompleteResult, error) {
	return nil, nil
}
func (b *fakeBackend) ClaimShare(_ context.Context, _ string) (*apidaemon.CeremonyClaimShareResult, error) {
	return nil, nil
}
func (b *fakeBackend) SignCSR(_ context.Context, _ *apidaemon.CeremonySignCSRRequest) (*apidaemon.CeremonySignCSRResult, error) {
	return nil, nil
}

type fakeStateProvider struct{ s rest.PlatformState }

func (p *fakeStateProvider) State(_ context.Context) rest.PlatformState { return p.s }

func TestBarrierInitService_NilBackend(t *testing.T) {
	svc := &barrierInitService{}
	_, err := svc.Initialize(context.Background(), &rest.BarrierInitRequest{})
	if err == nil {
		t.Fatal("expected error when backend is nil")
	}
	if _, ok := err.(*rest.ErrBarrierInitServiceUnavailable); !ok {
		t.Errorf("expected ErrBarrierInitServiceUnavailable, got %T", err)
	}
}

func TestBarrierInitService_PropagatesRequestFields(t *testing.T) {
	backend := &fakeBackend{
		resp: &apidaemon.CeremonyInitResult{CeremonyID: "c1"},
	}
	svc := &barrierInitService{
		backend: backend,
		state:   &fakeStateProvider{s: rest.PlatformStateUninitialized},
	}
	resp, err := svc.Initialize(context.Background(), &rest.BarrierInitRequest{
		SOPIN:                  "sopin",
		UserPIN:                "userpin",
		Shares:                 5,
		Threshold:              2,
		Hostname:               "host.example",
		SANs:                   []string{"a.example", "b.example"},
		CredentialSealStrategy: "software",
	})
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if backend.called != 1 {
		t.Errorf("backend called %d times, want 1", backend.called)
	}
	if backend.last.SOPIN != "sopin" {
		t.Errorf("SOPIN: got %q want sopin", backend.last.SOPIN)
	}
	if backend.last.UserPIN != "userpin" {
		t.Errorf("UserPIN: got %q want userpin", backend.last.UserPIN)
	}
	if backend.last.Threshold != "2-of-5" {
		t.Errorf("Threshold: got %q want 2-of-5", backend.last.Threshold)
	}
	if backend.last.Hostname != "host.example" {
		t.Errorf("Hostname: got %q want host.example", backend.last.Hostname)
	}
	if len(backend.last.SANs) != 2 {
		t.Errorf("SANs: got %v", backend.last.SANs)
	}
	if backend.last.CredentialSealStrategy != "software" {
		t.Errorf("CredentialSealStrategy: got %q", backend.last.CredentialSealStrategy)
	}
	if resp.CeremonyID != "c1" {
		t.Errorf("CeremonyID: got %q want c1", resp.CeremonyID)
	}
}

func TestBarrierInitService_BackendErrorBubblesUp(t *testing.T) {
	backend := &fakeBackend{err: errors.New("boom")}
	svc := &barrierInitService{
		backend: backend,
		state:   &fakeStateProvider{s: rest.PlatformStateUninitialized},
	}
	_, err := svc.Initialize(context.Background(), &rest.BarrierInitRequest{})
	if err == nil || err.Error() != "boom" {
		t.Errorf("expected backend error, got %v", err)
	}
}

func TestBarrierInitService_NilRequestUsesDefaults(t *testing.T) {
	backend := &fakeBackend{resp: &apidaemon.CeremonyInitResult{}}
	svc := &barrierInitService{
		backend: backend,
		state:   &fakeStateProvider{s: rest.PlatformStateUninitialized},
	}
	_, err := svc.Initialize(context.Background(), nil)
	if err != nil {
		t.Fatalf("Initialize(nil): %v", err)
	}
	if backend.last == nil {
		t.Fatal("backend should still be called with empty request")
	}
}

// =============================================================================
// Errors
// =============================================================================

func TestErrBarrierGateRequiresApp(t *testing.T) {
	if (ErrBarrierGateRequiresApp{}).Error() == "" {
		t.Error("expected non-empty error")
	}
}

func TestErrBarrierGateRequiresSDK(t *testing.T) {
	if (ErrBarrierGateRequiresSDK{}).Error() == "" {
		t.Error("expected non-empty error")
	}
}

func TestErrBarrierUnsealMissingSecret(t *testing.T) {
	if (ErrBarrierUnsealMissingSecret{}).Error() == "" {
		t.Error("expected non-empty error")
	}
}

// =============================================================================
// barrierUnsealService
// =============================================================================

func TestBarrierUnsealService_NilManager(t *testing.T) {
	svc := &barrierUnsealService{}
	_, err := svc.Unseal(context.Background(), &rest.BarrierUnsealRequest{Secret: "k"})
	if err == nil {
		t.Fatal("expected error when manager is nil")
	}
	if _, ok := err.(*rest.ErrBarrierUnsealServiceUnavailable); !ok {
		t.Errorf("expected ErrBarrierUnsealServiceUnavailable, got %T", err)
	}
}

// =============================================================================
// defaultBarrierGateConfig
// =============================================================================

func TestDefaultBarrierGateConfig(t *testing.T) {
	cfg := defaultBarrierGateConfig()
	if cfg.socketPath == "" {
		t.Error("socketPath default must be non-empty")
	}
	if cfg.httpAddr == "" {
		t.Error("httpAddr default must be non-empty")
	}
	if cfg.pollEvery <= 0 {
		t.Error("pollEvery default must be positive")
	}
}
