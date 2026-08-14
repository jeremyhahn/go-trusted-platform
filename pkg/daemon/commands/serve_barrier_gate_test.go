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
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	apidaemon "github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
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
func (b *fakeBackend) ClaimShareBegin(_ context.Context, _ *apidaemon.CeremonyClaimShareBeginRequest) (*apidaemon.CeremonyClaimShareBeginResult, error) {
	return nil, nil
}
func (b *fakeBackend) ClaimShareComplete(_ context.Context, _ *apidaemon.CeremonyClaimShareCompleteRequest) (*apidaemon.CeremonyClaimShareResult, error) {
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

// =============================================================================
// defaultBarrierGateHTTPAddr / port assignment
// =============================================================================

// TestDefaultBarrierGateHTTPAddr_Is9446 pins the gate's default loopback
// bind address to 127.0.0.1:9446. The previous value (9445) collided with
// the production MCP listener; regressing to 9445 would cause the gate
// to fight MCP for the same port at boot.
func TestDefaultBarrierGateHTTPAddr_Is9446(t *testing.T) {
	if defaultBarrierGateHTTPAddr != "127.0.0.1:9446" {
		t.Errorf("defaultBarrierGateHTTPAddr = %q, want %q (must not collide with MCP on :9445)",
			defaultBarrierGateHTTPAddr, "127.0.0.1:9446")
	}
	if defaultBarrierGateConfig().httpAddr != "127.0.0.1:9446" {
		t.Errorf("defaultBarrierGateConfig().httpAddr = %q, want %q",
			defaultBarrierGateConfig().httpAddr, "127.0.0.1:9446")
	}
}

// =============================================================================
// invokeBarrierGate / initOnlyGate hook
// =============================================================================

// fakeInitOnlyGate records each invocation of the M6 gate so tests can
// assert that runWithWebservices and runDaemonOnly both reach the gate.
// The recorded gate config lets us verify that the CLI socket path is
// threaded through to the listener.
type fakeInitOnlyGate struct {
	called    int
	lastApp   *app.App
	lastCfg   barrierGateConfig
	returnErr error
}

func (f *fakeInitOnlyGate) run(_ context.Context, a *app.App, _ *logging.Logger, cfg barrierGateConfig) error {
	f.called++
	f.lastApp = a
	f.lastCfg = cfg
	return f.returnErr
}

// withFakeGate swaps initOnlyGate for the duration of a test and restores
// the production hook on cleanup. Tests use this to assert the gate is
// invoked without standing up a real Unix socket / HTTP listener.
func withFakeGate(t *testing.T, fake *fakeInitOnlyGate) {
	t.Helper()
	prev := initOnlyGate
	initOnlyGate = fake.run
	t.Cleanup(func() { initOnlyGate = prev })
}

// withSocketPath swaps the package-level serveSocketPath CLI flag for the
// duration of a test and restores the prior value on cleanup. The gate
// helper reads this variable to thread the operator-configured socket
// path into the init-only listener.
func withSocketPath(t *testing.T, path string) {
	t.Helper()
	prev := serveSocketPath
	serveSocketPath = path
	t.Cleanup(func() { serveSocketPath = prev })
}

// TestInvokeBarrierGate_DispatchesViaHook proves invokeBarrierGate routes
// through the swappable initOnlyGate hook. This is the seam both
// runWithWebservices and runDaemonOnly use to call the gate.
func TestInvokeBarrierGate_DispatchesViaHook(t *testing.T) {
	fake := &fakeInitOnlyGate{}
	withFakeGate(t, fake)
	withSocketPath(t, "/tmp/test-platformd.sock")

	logger := logging.NewLogger(0, nil)
	if err := invokeBarrierGate(context.Background(), nil, logger); err != nil {
		t.Fatalf("invokeBarrierGate: unexpected error %v", err)
	}
	if fake.called != 1 {
		t.Errorf("fake gate called %d times, want 1", fake.called)
	}
}

// TestInvokeBarrierGate_ThreadsSocketPath confirms the operator-configured
// --socket-path CLI value is threaded into the gate config. Without this,
// the gate would bind /run/platformd.sock and the production daemon would
// silently bind whatever the CLI specified, leaving local platformctl
// pointed at the wrong socket during the unseal window.
func TestInvokeBarrierGate_ThreadsSocketPath(t *testing.T) {
	fake := &fakeInitOnlyGate{}
	withFakeGate(t, fake)
	withSocketPath(t, "/var/run/custom-platformd.sock")

	logger := logging.NewLogger(0, nil)
	if err := invokeBarrierGate(context.Background(), nil, logger); err != nil {
		t.Fatalf("invokeBarrierGate: %v", err)
	}
	if fake.lastCfg.socketPath != "/var/run/custom-platformd.sock" {
		t.Errorf("gate socketPath = %q, want %q",
			fake.lastCfg.socketPath, "/var/run/custom-platformd.sock")
	}
	if fake.lastCfg.httpAddr != defaultBarrierGateHTTPAddr {
		t.Errorf("gate httpAddr = %q, want default %q",
			fake.lastCfg.httpAddr, defaultBarrierGateHTTPAddr)
	}
	if fake.lastCfg.pollEvery <= 0 {
		t.Errorf("gate pollEvery = %v, want positive default", fake.lastCfg.pollEvery)
	}
}

// TestInvokeBarrierGate_PropagatesError ensures gate failures reach the
// caller so runWithWebservices/runDaemonOnly can abort before binding
// production listeners. Treating the gate as fallible-but-fatal is the
// whole point of M6: a sealed barrier MUST keep remote transports dark.
func TestInvokeBarrierGate_PropagatesError(t *testing.T) {
	sentinel := errors.New("gate-down")
	fake := &fakeInitOnlyGate{returnErr: sentinel}
	withFakeGate(t, fake)
	withSocketPath(t, "/tmp/x.sock")

	logger := logging.NewLogger(0, nil)
	err := invokeBarrierGate(context.Background(), nil, logger)
	if !errors.Is(err, sentinel) {
		t.Errorf("invokeBarrierGate err = %v, want %v", err, sentinel)
	}
}

// =============================================================================
// Entry-point wiring: runWithWebservices + runDaemonOnly both call the gate
// =============================================================================

// TestRunWithWebservices_InvokesBarrierGate enforces — at the source level
// — that runWithWebservices calls invokeBarrierGate. A purely runtime
// assertion is impractical because runWithWebservices requires a fully
// initialized App (CA, web services, SDK client) before the gate is
// reached, and standing all of that up in a unit test would violate the
// "never run heavy logic in unit tests" rule from CLAUDE.md.
//
// The check uses Go's parser so a comment containing the text doesn't
// produce a false positive. We walk the function body and look for an
// identifier call to invokeBarrierGate.
func TestRunWithWebservices_InvokesBarrierGate(t *testing.T) {
	if !functionCallsHelper(t, "runWithWebservices", "invokeBarrierGate") {
		t.Errorf("runWithWebservices does not call invokeBarrierGate; the M6 gate is bypassed in webservices mode")
	}
}

// TestRunDaemonOnly_InvokesBarrierGate enforces the same wiring guarantee
// for the daemon-only entry point. See TestRunWithWebservices_InvokesBarrierGate
// for why this is a source-level rather than runtime test.
func TestRunDaemonOnly_InvokesBarrierGate(t *testing.T) {
	if !functionCallsHelper(t, "runDaemonOnly", "invokeBarrierGate") {
		t.Errorf("runDaemonOnly does not call invokeBarrierGate; the M6 gate is bypassed in daemon-only mode")
	}
}

// functionCallsHelper parses serve.go and reports whether the named
// function's body contains a call to the named helper. The check is
// AST-based so source comments referencing the helper don't produce
// false positives.
func functionCallsHelper(t *testing.T, fnName, helper string) bool {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "serve.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse serve.go: %v", err)
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name == nil || fn.Name.Name != fnName || fn.Body == nil {
			continue
		}
		found := false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			ident, ok := call.Fun.(*ast.Ident)
			if !ok {
				return true
			}
			if ident.Name == helper {
				found = true
				return false
			}
			return true
		})
		return found
	}
	t.Fatalf("function %q not found in serve.go", fnName)
	return false
}
