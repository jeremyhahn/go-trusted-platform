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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"

	apidaemon "github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/barrier"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util/peercred"
)

// =============================================================================
// barrierStateProvider
// =============================================================================

// fakeGateBarrier is an in-memory gateBarrier. Its flags move the way
// barrier.Manager's cached flags do.
type fakeGateBarrier struct {
	initialized bool
	sealed      bool
	unsealing   bool

	initSecret   string
	unsealSecret string
	syncCalls    int

	initErr   error
	syncErr   error
	unsealErr error
	shareResp *quicbaassdk.QRDBBarrierUnsealShareResponse
	shareErr  error
}

func (f *fakeGateBarrier) Initialize(_ context.Context, secret string) error {
	f.initSecret = secret
	if f.initErr != nil {
		return f.initErr
	}
	f.initialized = true
	f.sealed = false
	return nil
}

// InitializeShamir and Status complete the barrierLifecycle surface; the
// gate tests that use this fake run the single-key barrier, so a Shamir
// initialize reaching it is a defect.
func (f *fakeGateBarrier) InitializeShamir(_ context.Context, _ string, _, _ int) (*quicbaassdk.QRDBBarrierInitializeShamirResponse, error) {
	return nil, &errUnexpectedShamirInit{}
}

func (f *fakeGateBarrier) RegisterOfficer(context.Context, string, []byte) error {
	return &errUnexpectedShamirInit{}
}

func (f *fakeGateBarrier) Officers(context.Context) ([]string, error) {
	return nil, &errUnexpectedShamirInit{}
}

// errUnexpectedShamirInit is what fakeGateBarrier returns when a Shamir
// initialize reaches it.
type errUnexpectedShamirInit struct{}

func (e *errUnexpectedShamirInit) Error() string {
	return "fakeGateBarrier: unexpected Shamir initialize"
}

func (f *fakeGateBarrier) Status(_ context.Context) (*quicbaassdk.QRDBBarrierStatusResponse, error) {
	return &quicbaassdk.QRDBBarrierStatusResponse{Strategy: barrier.SealStrategySoftware, Sealed: f.sealed}, nil
}

func (f *fakeGateBarrier) SyncStatus(_ context.Context) error {
	f.syncCalls++
	return f.syncErr
}

func (f *fakeGateBarrier) Unseal(_ context.Context, secret string) error {
	f.unsealSecret = secret
	if f.unsealErr != nil {
		return f.unsealErr
	}
	f.sealed = false
	f.unsealing = false
	return nil
}

func (f *fakeGateBarrier) UnsealWithShare(_ context.Context, _ string) (*quicbaassdk.QRDBBarrierUnsealShareResponse, error) {
	if f.shareErr != nil {
		return nil, f.shareErr
	}
	if f.shareResp.Complete {
		f.sealed = false
		f.unsealing = false
	} else {
		f.unsealing = f.shareResp.Submitted > 0
	}
	return f.shareResp, nil
}

func (f *fakeGateBarrier) IsInitialized() bool { return f.initialized }
func (f *fakeGateBarrier) IsSealed() bool      { return f.sealed }
func (f *fakeGateBarrier) IsUnsealing() bool   { return f.sealed && f.unsealing }

func TestBarrierStateProvider_NilBarrier(t *testing.T) {
	p := &barrierStateProvider{barrier: nil}
	if got := p.State(context.Background()); got != rest.PlatformStateUninitialized {
		t.Errorf("nil barrier: got %q want uninitialized", got)
	}
}

func TestBarrierStateProvider_ReportsEveryState(t *testing.T) {
	cases := []struct {
		name    string
		barrier *fakeGateBarrier
		want    rest.PlatformState
	}{
		{"uninitialized", &fakeGateBarrier{}, rest.PlatformStateUninitialized},
		{"sealed", &fakeGateBarrier{initialized: true, sealed: true}, rest.PlatformStateSealed},
		{"unsealing", &fakeGateBarrier{initialized: true, sealed: true, unsealing: true}, rest.PlatformStateUnsealing},
		{"unsealed", &fakeGateBarrier{initialized: true}, rest.PlatformStateUnsealed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &barrierStateProvider{barrier: tc.barrier}
			if got := p.State(context.Background()); got != tc.want {
				t.Errorf("got %q want %q", got, tc.want)
			}
		})
	}
}

// TestGateBarrierOf_NilManagerIsNilInterface guards the nil-interface trap:
// an app with no manager must yield a nil gateBarrier, or the gate would
// wire services around a nil *barrier.Manager.
func TestGateBarrierOf_NilManagerIsNilInterface(t *testing.T) {
	if got := gateBarrierOf(nil); got != nil {
		t.Errorf("nil app: got %T, want nil", got)
	}
	if got := gateBarrierOf(&app.App{}); got != nil {
		t.Errorf("app without a manager: got %T, want nil", got)
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
		resp: &apidaemon.CeremonyInitResult{
			CeremonyID: "c1", AdminCertPEM: "ADMIN-CERT", AdminKeyPEM: "ADMIN-KEY", SPKIPin: "PIN",
		},
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
		Officers:               testOfficers(t, 5),
	})
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if len(backend.last.Officers) != 5 || backend.last.Officers[4].Username != "officer-5" || backend.last.Officers[4].CSRPEM == "" {
		t.Errorf("Officers not carried to the ceremony: %+v", backend.last.Officers)
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
	if resp.AdminCertPEM != "ADMIN-CERT" || resp.AdminKeyPEM != "ADMIN-KEY" || resp.SPKIPin != "PIN" {
		t.Errorf("admin bundle not carried into the /init response: %+v", resp)
	}
}

func TestBarrierInitService_BackendErrorBubblesUp(t *testing.T) {
	backend := &fakeBackend{err: errors.New("boom")}
	svc := &barrierInitService{
		backend: backend,
		state:   &fakeStateProvider{s: rest.PlatformStateUninitialized},
	}
	_, err := svc.Initialize(context.Background(), &rest.BarrierInitRequest{UserPIN: "user"})
	if err == nil || err.Error() != "boom" {
		t.Errorf("expected backend error, got %v", err)
	}
}

// TestBarrierInitService_NilRequestRefused covers a body with no user PIN:
// no strategy can initialize the barrier without it, so the ceremony must
// not run and mint a bundle for a barrier that will stay uninitialized.
func TestBarrierInitService_NilRequestRefused(t *testing.T) {
	backend := &fakeBackend{resp: &apidaemon.CeremonyInitResult{}}
	svc := &barrierInitService{
		backend: backend,
		state:   &fakeStateProvider{s: rest.PlatformStateUninitialized},
	}
	_, err := svc.Initialize(context.Background(), nil)
	var missing *ErrBarrierInitMissingSecret
	if !errors.As(err, &missing) {
		t.Fatalf("Initialize(nil): got %v, want ErrBarrierInitMissingSecret", err)
	}
	if backend.called != 0 {
		t.Errorf("ceremony ran %d times for a refused request", backend.called)
	}
}

// fakeBarrierLifecycle records which barrier lifecycle operation /init
// dispatched to.
type fakeBarrierLifecycle struct {
	initialized bool
	err         error

	// strategy is the seal strategy Status reports as registered.
	strategy  string
	statusErr error

	initCalls  int
	initSecret string

	shamirCalls     int
	shamirSecret    string
	shamirThreshold int
	shamirShares    int

	// registered is the officer set the barrier's share ceremony holds.
	// InitializeShamir refuses a set that does not match the share count, as
	// the SDK's share distribution does.
	registered  []string
	registerErr error
	officersErr error
}

// errOfficerCountMismatch stands in for the SDK refusing to distribute shares
// to an officer set that does not match the share count.
type errOfficerCountMismatch struct{}

func (e *errOfficerCountMismatch) Error() string { return "officer count does not match share count" }

// errDuplicateOfficer stands in for the SDK refusing to register a username
// twice.
type errDuplicateOfficer struct{}

func (e *errDuplicateOfficer) Error() string { return "officer already registered" }

func (f *fakeBarrierLifecycle) RegisterOfficer(_ context.Context, username string, _ []byte) error {
	if f.registerErr != nil {
		return f.registerErr
	}
	for _, known := range f.registered {
		if known == username {
			return &errDuplicateOfficer{}
		}
	}
	f.registered = append(f.registered, username)
	return nil
}

func (f *fakeBarrierLifecycle) Officers(context.Context) ([]string, error) {
	return f.registered, f.officersErr
}

func (f *fakeBarrierLifecycle) IsInitialized() bool { return f.initialized }

func (f *fakeBarrierLifecycle) Initialize(_ context.Context, secret string) error {
	f.initCalls++
	f.initSecret = secret
	return f.err
}

func (f *fakeBarrierLifecycle) InitializeShamir(_ context.Context, secret string, threshold, shares int) (*quicbaassdk.QRDBBarrierInitializeShamirResponse, error) {
	f.shamirCalls++
	f.shamirSecret = secret
	f.shamirThreshold = threshold
	f.shamirShares = shares
	if f.err != nil {
		return nil, f.err
	}
	if len(f.registered) != shares {
		return nil, &errOfficerCountMismatch{}
	}
	return &quicbaassdk.QRDBBarrierInitializeShamirResponse{Threshold: threshold, TotalShares: shares, ShareCount: shares}, nil
}

func (f *fakeBarrierLifecycle) Status(_ context.Context) (*quicbaassdk.QRDBBarrierStatusResponse, error) {
	if f.statusErr != nil {
		return nil, f.statusErr
	}
	return &quicbaassdk.QRDBBarrierStatusResponse{Strategy: f.strategy}, nil
}

func (f *fakeBarrierLifecycle) SyncStatus(_ context.Context) error { return nil }

func dispatchingInitService(defaultStrategy string) (*barrierInitService, *fakeBackend, *fakeBarrierLifecycle) {
	svc, backend := issuingInitService()
	lifecycle := &fakeBarrierLifecycle{strategy: barrier.SealStrategySoftware}
	svc.barrier = lifecycle
	svc.defaultStrategy = defaultStrategy
	return svc, backend, lifecycle
}

// shamirInitService is dispatchingInitService over a barrier sealed by the
// Shamir strategy, the only barrier a shamir request may initialize.
func shamirInitService(defaultStrategy string) (*barrierInitService, *fakeBackend, *fakeBarrierLifecycle) {
	svc, backend, lifecycle := dispatchingInitService(defaultStrategy)
	lifecycle.strategy = barrier.SealStrategyShamir
	return svc, backend, lifecycle
}

// TestBarrierInitService_SingleKeyStrategies covers every strategy whose
// barrier is initialized with one secret: the user PIN goes to
// Manager.Initialize and the Shamir path is never taken.
func TestBarrierInitService_SingleKeyStrategies(t *testing.T) {
	for _, strategy := range []string{"software", "passphrase", "tpm2", "pkcs11", "awskms", "gcpkms", "azurekv", "vault"} {
		t.Run(strategy, func(t *testing.T) {
			svc, backend, lifecycle := dispatchingInitService(strategy)
			_, err := svc.Initialize(context.Background(), &rest.BarrierInitRequest{
				SOPIN: "so", UserPIN: "user",
			})
			if err != nil {
				t.Fatalf("Initialize: %v", err)
			}
			if backend.called != 1 {
				t.Errorf("ceremony ran %d times, want 1", backend.called)
			}
			if lifecycle.initCalls != 1 || lifecycle.initSecret != "user" {
				t.Errorf("Initialize calls=%d secret=%q, want 1 with the user PIN", lifecycle.initCalls, lifecycle.initSecret)
			}
			if lifecycle.shamirCalls != 0 {
				t.Errorf("InitializeShamir called %d times for %s", lifecycle.shamirCalls, strategy)
			}
		})
	}
}

// TestBarrierInitService_ShamirStrategy covers barrier.seal_strategy=shamir:
// the barrier is split M-of-N rather than silently becoming single-key.
func TestBarrierInitService_ShamirStrategy(t *testing.T) {
	svc, _, lifecycle := shamirInitService("shamir")
	_, err := svc.Initialize(context.Background(), &rest.BarrierInitRequest{
		SOPIN: "so", UserPIN: "user", Threshold: 2, Shares: 3, Officers: testOfficers(t, 3),
	})
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if len(lifecycle.registered) != 3 {
		t.Errorf("registered %v with the barrier, want the 3 officers", lifecycle.registered)
	}
	if lifecycle.shamirCalls != 1 {
		t.Fatalf("InitializeShamir called %d times, want 1", lifecycle.shamirCalls)
	}
	if lifecycle.shamirSecret != "user" || lifecycle.shamirThreshold != 2 || lifecycle.shamirShares != 3 {
		t.Errorf("InitializeShamir(%q, %d, %d), want (user, 2, 3)",
			lifecycle.shamirSecret, lifecycle.shamirThreshold, lifecycle.shamirShares)
	}
	if lifecycle.initCalls != 0 {
		t.Errorf("single-key Initialize called %d times for shamir", lifecycle.initCalls)
	}
}

// TestBarrierInitService_StrategyResolution covers where the strategy comes
// from: the daemon's configured barrier seal strategy, else the built-in
// default. The request cannot select one.
func TestBarrierInitService_StrategyResolution(t *testing.T) {
	t.Run("credential seal strategy is not the barrier strategy", func(t *testing.T) {
		svc, _, lifecycle := shamirInitService("")
		_, err := svc.Initialize(context.Background(), &rest.BarrierInitRequest{
			UserPIN: "user", CredentialSealStrategy: "shamir", Threshold: 2, Shares: 2, Officers: testOfficers(t, 2),
		})
		if err != nil {
			t.Fatalf("Initialize: %v", err)
		}
		if lifecycle.shamirCalls != 0 || lifecycle.initCalls != 1 {
			t.Errorf("credential_seal_strategy selected the barrier strategy: init=%d shamir=%d",
				lifecycle.initCalls, lifecycle.shamirCalls)
		}
	})
	t.Run("configured default", func(t *testing.T) {
		svc, _, lifecycle := shamirInitService("shamir")
		_, err := svc.Initialize(context.Background(), &rest.BarrierInitRequest{
			UserPIN: "user", Threshold: 3, Shares: 5, Officers: testOfficers(t, 5),
		})
		if err != nil {
			t.Fatalf("Initialize: %v", err)
		}
		if lifecycle.shamirCalls != 1 {
			t.Errorf("configured shamir strategy did not reach InitializeShamir")
		}
	})
	t.Run("built-in default", func(t *testing.T) {
		svc, _, lifecycle := dispatchingInitService("")
		if _, err := svc.Initialize(context.Background(), &rest.BarrierInitRequest{UserPIN: "user"}); err != nil {
			t.Fatalf("Initialize: %v", err)
		}
		if lifecycle.initCalls != 1 {
			t.Errorf("no strategy anywhere did not fall back to the single-key barrier")
		}
	})
}

// TestBarrierInitService_RefusedBeforeCeremony covers requests no barrier
// operation can honour. Each is refused as an invalid request before the
// ceremony mints the one-shot admin bundle.
func TestBarrierInitService_RefusedBeforeCeremony(t *testing.T) {
	cases := []struct {
		name     string
		strategy string
		req      *rest.BarrierInitRequest
		want     any
	}{
		{"missing user PIN", "tpm2", &rest.BarrierInitRequest{SOPIN: "so"}, new(*ErrBarrierInitMissingSecret)},
		{"shamir threshold below 2", "shamir", &rest.BarrierInitRequest{UserPIN: "user", Threshold: 1, Shares: 3}, new(*ErrBarrierShamirQuorum)},
		{"shamir threshold above shares", "shamir", &rest.BarrierInitRequest{UserPIN: "user", Threshold: 4, Shares: 3}, new(*ErrBarrierShamirQuorum)},
		{"shamir without quorum", "shamir", &rest.BarrierInitRequest{UserPIN: "user"}, new(*ErrBarrierShamirQuorum)},
		{"shamir without officers", "shamir", &rest.BarrierInitRequest{UserPIN: "user", Threshold: 2, Shares: 3}, new(*ErrBarrierInitOfficers)},
		{"shamir with too few officers", "shamir", &rest.BarrierInitRequest{UserPIN: "user", Threshold: 2, Shares: 3, Officers: testOfficers(t, 2)}, new(*ErrBarrierInitOfficers)},
		{"officers without a quorum", "tpm2", &rest.BarrierInitRequest{UserPIN: "user", Officers: testOfficers(t, 1)}, new(*ErrBarrierInitOfficers)},
		{"officer without username", "shamir", &rest.BarrierInitRequest{UserPIN: "user", Threshold: 2, Shares: 2, Officers: withOfficer(testOfficers(t, 2), 1, "", "")}, new(*ErrBarrierInitOfficerInvalid)},
		{"duplicate officer", "shamir", &rest.BarrierInitRequest{UserPIN: "user", Threshold: 2, Shares: 2, Officers: withOfficer(testOfficers(t, 2), 1, "officer-1", "")}, new(*ErrBarrierInitOfficerInvalid)},
		{"officer CSR not PEM", "shamir", &rest.BarrierInitRequest{UserPIN: "user", Threshold: 2, Shares: 2, Officers: withOfficer(testOfficers(t, 2), 0, "officer-1", "not a csr")}, new(*ErrBarrierInitOfficerCSRNotPEM)},
		{"officer CSR not a CSR", "shamir", &rest.BarrierInitRequest{UserPIN: "user", Threshold: 2, Shares: 2, Officers: withOfficer(testOfficers(t, 2), 0, "officer-1", "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n")}, new(*ErrBarrierInitOfficerInvalid)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, backend, lifecycle := dispatchingInitService(tc.strategy)
			_, err := svc.Initialize(context.Background(), tc.req)
			var invalid *rest.ErrInitInvalidRequest
			if !errors.As(err, &invalid) {
				t.Fatalf("got %v, want rest.ErrInitInvalidRequest", err)
			}
			if !errors.As(err, tc.want) {
				t.Errorf("got %v, want %T", err, tc.want)
			}
			if backend.called != 0 || lifecycle.initCalls != 0 || lifecycle.shamirCalls != 0 {
				t.Errorf("refused request reached ceremony=%d init=%d shamir=%d",
					backend.called, lifecycle.initCalls, lifecycle.shamirCalls)
			}
		})
	}
}

// TestBarrierInitService_UnsupportedConfiguredStrategy covers a configured
// barrier.seal_strategy /init cannot initialize the barrier with. It is a
// daemon configuration fault, not a caller mistake, so it is not reported as
// an invalid request, and it is refused before the ceremony runs.
func TestBarrierInitService_UnsupportedConfiguredStrategy(t *testing.T) {
	for _, strategy := range []string{"none", "bogus"} {
		t.Run(strategy, func(t *testing.T) {
			svc, backend, lifecycle := dispatchingInitService(strategy)
			_, err := svc.Initialize(context.Background(), &rest.BarrierInitRequest{SOPIN: "so", UserPIN: "user"})
			var unsupported *ErrBarrierStrategyUnsupported
			if !errors.As(err, &unsupported) || unsupported.Strategy != strategy {
				t.Fatalf("got %v, want ErrBarrierStrategyUnsupported{%q}", err, strategy)
			}
			var invalid *rest.ErrInitInvalidRequest
			if errors.As(err, &invalid) {
				t.Errorf("a configuration fault was reported as an invalid request: %v", err)
			}
			if backend.called != 0 || lifecycle.initCalls != 0 || lifecycle.shamirCalls != 0 {
				t.Errorf("refused request reached ceremony=%d init=%d shamir=%d",
					backend.called, lifecycle.initCalls, lifecycle.shamirCalls)
			}
		})
	}
}

// TestBarrierInitService_ShamirRefusedOnUnenforceableBarrier covers a shamir
// request on a barrier the Shamir strategy does not seal. InitializeShamir
// would run in credential mode there and let the user PIN unseal alone, so the
// request is refused as a barrier conflict before the ceremony runs, and
// nothing is initialized.
func TestBarrierInitService_ShamirRefusedOnUnenforceableBarrier(t *testing.T) {
	req := &rest.BarrierInitRequest{SOPIN: "so", UserPIN: "user", Threshold: 2, Shares: 3, Officers: testOfficers(t, 3)}
	for _, registered := range []string{barrier.SealStrategySoftware, "passphrase", "tpm2", ""} {
		t.Run("registered "+registered, func(t *testing.T) {
			svc, backend, lifecycle := dispatchingInitService("shamir")
			lifecycle.strategy = registered
			_, err := svc.Initialize(context.Background(), req)
			var conflict *rest.ErrInitBarrierConflict
			if !errors.As(err, &conflict) {
				t.Fatalf("got %v, want rest.ErrInitBarrierConflict", err)
			}
			var unenforceable *ErrBarrierShamirUnenforceable
			if !errors.As(err, &unenforceable) || unenforceable.Registered != registered {
				t.Errorf("got %v, want ErrBarrierShamirUnenforceable{Registered: %q}", err, registered)
			}
			if backend.called != 0 || lifecycle.initCalls != 0 || lifecycle.shamirCalls != 0 {
				t.Errorf("refused request reached ceremony=%d init=%d shamir=%d",
					backend.called, lifecycle.initCalls, lifecycle.shamirCalls)
			}
		})
	}
	t.Run("no barrier manager", func(t *testing.T) {
		svc, backend := issuingInitService()
		svc.defaultStrategy = barrier.SealStrategyShamir
		_, err := svc.Initialize(context.Background(), req)
		var conflict *rest.ErrInitBarrierConflict
		if !errors.As(err, &conflict) {
			t.Fatalf("got %v, want rest.ErrInitBarrierConflict", err)
		}
		if backend.called != 0 {
			t.Errorf("refused request ran the ceremony %d times", backend.called)
		}
	})
}

// TestBarrierInitService_ShamirRefusedWhenStatusUnavailable covers a barrier
// whose strategy cannot be read: the quorum is never assumed, the error is not
// a client conflict, and the ceremony does not run.
func TestBarrierInitService_ShamirRefusedWhenStatusUnavailable(t *testing.T) {
	svc, backend, lifecycle := shamirInitService("shamir")
	cause := errors.New("status read failed")
	lifecycle.statusErr = cause
	_, err := svc.Initialize(context.Background(), &rest.BarrierInitRequest{
		UserPIN: "user", Threshold: 2, Shares: 3, Officers: testOfficers(t, 3),
	})
	var unavailable *ErrBarrierStatusUnavailable
	if !errors.As(err, &unavailable) || !errors.Is(err, cause) {
		t.Fatalf("got %v, want ErrBarrierStatusUnavailable wrapping the cause", err)
	}
	var conflict *rest.ErrInitBarrierConflict
	if errors.As(err, &conflict) {
		t.Errorf("status failure reported as a client conflict: %v", err)
	}
	if backend.called != 0 || lifecycle.shamirCalls != 0 {
		t.Errorf("refused request reached ceremony=%d shamir=%d", backend.called, lifecycle.shamirCalls)
	}
}

// TestBarrierInitService_SingleKeySkipsStrategyCheck covers a single-key
// request: the registered strategy is not consulted, so a status failure
// cannot block it.
func TestBarrierInitService_SingleKeySkipsStrategyCheck(t *testing.T) {
	svc, _, lifecycle := dispatchingInitService("")
	lifecycle.statusErr = errors.New("status read failed")
	if _, err := svc.Initialize(context.Background(), &rest.BarrierInitRequest{UserPIN: "user"}); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if lifecycle.initCalls != 1 {
		t.Errorf("single-key Initialize called %d times, want 1", lifecycle.initCalls)
	}
}

// TestBarrierInitService_InitializedBarrierNotReinitialized covers an
// identical retry after the barrier itself was initialized: the lifecycle
// operation is not invoked a second time.
func TestBarrierInitService_InitializedBarrierNotReinitialized(t *testing.T) {
	svc, _, lifecycle := dispatchingInitService("")
	lifecycle.initialized = true
	if _, err := svc.Initialize(context.Background(), &rest.BarrierInitRequest{UserPIN: "user"}); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if lifecycle.initCalls != 0 {
		t.Errorf("initialized barrier was initialized again")
	}
}

func TestBarrierInitErrors_Messages(t *testing.T) {
	cases := map[string]error{
		`"none"`:                  &ErrBarrierStrategyUnsupported{Strategy: "none"},
		`"tpm2"`:                  &ErrBarrierInitMissingSecret{Strategy: "tpm2"},
		"threshold 4":             &ErrBarrierShamirQuorum{Threshold: 4, Shares: 3},
		"of 3 shares":             &ErrBarrierShamirQuorum{Threshold: 4, Shares: 3},
		`"software"`:              &ErrBarrierShamirUnenforceable{Registered: "software"},
		"no barrier":              &ErrBarrierShamirUnenforceable{},
		"read failed":             &ErrBarrierStatusUnavailable{Err: errors.New("read failed")},
		"2 officers for 3 shares": &ErrBarrierInitOfficers{Officers: 2, Shares: 3},
		`officer 1 "bob"`:         &ErrBarrierInitOfficerInvalid{Index: 1, Username: "bob", Reason: "duplicate username"},
		"duplicate username":      &ErrBarrierInitOfficerInvalid{Index: 1, Username: "bob", Reason: "duplicate username"},
		"unusable csr_pem: bad":   &ErrBarrierInitOfficerInvalid{Reason: "unusable csr_pem", Err: errors.New("bad")},
		"no PEM block":            &ErrBarrierInitOfficerCSRNotPEM{},
	}
	for want, err := range cases {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%T.Error() = %q, want it to contain %q", err, err.Error(), want)
		}
	}
}

func issuingInitService() (*barrierInitService, *fakeBackend) {
	backend := &fakeBackend{resp: &apidaemon.CeremonyInitResult{
		CeremonyID: "c1", AdminCertPEM: "ADMIN-CERT", AdminKeyPEM: "ADMIN-KEY", SPKIPin: "PIN",
	}}
	return &barrierInitService{
		backend: backend,
		state:   &fakeStateProvider{s: rest.PlatformStateUninitialized},
	}, backend
}

// unixCaller is the request context of a caller on the Unix socket, as the
// gate's ConnContext builds it from SO_PEERCRED.
func unixCaller(uid uint32) context.Context {
	return peercred.ContextWithUnixCredentials(context.Background(), peercred.UnixCredentials{PID: 1, UID: uid})
}

// TestBarrierInitService_IdenticalRetryReplaysBundle covers a retry after
// the first response was lost: the same bundle comes back and the ceremony
// is not run (or the admin key minted) a second time.
func TestBarrierInitService_IdenticalRetryReplaysBundle(t *testing.T) {
	svc, backend := issuingInitService()
	req := &rest.BarrierInitRequest{SOPIN: "so", UserPIN: "user", SANs: []string{"a"}}
	if _, err := svc.Initialize(unixCaller(0), req); err != nil {
		t.Fatalf("first Initialize: %v", err)
	}
	retry := *req
	resp, err := svc.Initialize(unixCaller(0), &retry)
	if err != nil {
		t.Fatalf("retry Initialize: %v", err)
	}
	if backend.called != 1 {
		t.Errorf("backend called %d times, want 1", backend.called)
	}
	if resp.AdminKeyPEM != "ADMIN-KEY" || resp.AdminCertPEM != "ADMIN-CERT" || resp.SPKIPin != "PIN" {
		t.Errorf("retry lost the bundle: %+v", resp)
	}
}

// TestBarrierInitService_ReplayOnlyToIssuingUnixUID: the bundle is handed
// out again only over the Unix socket, and only to the uid it was issued
// to. Every other caller gets exactly the answer a wrong PIN gets, so the
// gate never confirms the PINs to anyone but the operator.
func TestBarrierInitService_ReplayOnlyToIssuingUnixUID(t *testing.T) {
	req := rest.BarrierInitRequest{SOPIN: "so", UserPIN: "user"}
	wrong := rest.BarrierInitRequest{SOPIN: "so", UserPIN: "guess"}
	cases := map[string]struct {
		issuer, caller context.Context
	}{
		"other uid on the socket":               {issuer: unixCaller(0), caller: unixCaller(1000)},
		"loopback HTTP caller":                  {issuer: unixCaller(0), caller: context.Background()},
		"issued over HTTP":                      {issuer: context.Background(), caller: context.Background()},
		"issued over HTTP, retry on the socket": {issuer: context.Background(), caller: unixCaller(0)},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			svc, backend := issuingInitService()
			first := req
			if _, err := svc.Initialize(tc.issuer, &first); err != nil {
				t.Fatalf("first Initialize: %v", err)
			}
			for _, attempt := range []rest.BarrierInitRequest{req, wrong} {
				_, err := svc.Initialize(tc.caller, &attempt)
				var issued *rest.ErrInitAlreadyIssued
				if !errors.As(err, &issued) {
					t.Errorf("Initialize(%q): want ErrInitAlreadyIssued, got %v", attempt.UserPIN, err)
				}
				if resp, ok := svc.Replay(tc.caller, &attempt); ok {
					t.Errorf("Replay(%q) handed out the bundle: %+v", attempt.UserPIN, resp)
				}
			}
			if backend.called != 1 {
				t.Errorf("backend called %d times, want 1", backend.called)
			}
		})
	}
}

// TestBarrierInitService_HoldsAdminKeyInEnclave: while the gate is up the
// admin key lives only in locked memory, never in the retained response.
func TestBarrierInitService_HoldsAdminKeyInEnclave(t *testing.T) {
	svc, _ := issuingInitService()
	if _, err := svc.Initialize(unixCaller(0), &rest.BarrierInitRequest{SOPIN: "so", UserPIN: "user"}); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if svc.issued.resp.AdminKeyPEM != "" {
		t.Error("the retained response holds the admin key in a plain string")
	}
	if !svc.issued.key.IsAlive() || !svc.issued.key.EqualBytes([]byte("ADMIN-KEY")) {
		t.Error("the admin key is not held in a live enclave")
	}
}

func TestBarrierInitService_ReleaseDestroysAdminKey(t *testing.T) {
	svc, _ := issuingInitService()
	req := &rest.BarrierInitRequest{SOPIN: "so", UserPIN: "user"}
	if _, err := svc.Initialize(unixCaller(0), req); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	key := svc.issued.key
	svc.release()
	if key.IsAlive() || key.Bytes() != nil {
		t.Error("release left the admin key readable")
	}
	if _, ok := svc.Replay(unixCaller(0), req); ok {
		t.Error("Replay handed out a released bundle")
	}
	var issued *rest.ErrInitAlreadyIssued
	if _, err := svc.Initialize(unixCaller(0), req); !errors.As(err, &issued) {
		t.Errorf("Initialize after release: want ErrInitAlreadyIssued, got %v", err)
	}
}

func TestBarrierInitService_ReleaseIsNilSafe(t *testing.T) {
	var nilSvc *barrierInitService
	nilSvc.release()
	(&barrierInitService{}).release()
}

// TestBarrierInitService_UnsealDestroysAdminKey: an init that leaves the
// barrier unsealed (software auto-unseal) returns the key once and keeps no
// copy, because the gate is about to close and nobody can replay it.
func TestBarrierInitService_UnsealDestroysAdminKey(t *testing.T) {
	svc, _ := issuingInitService()
	svc.state = &fakeStateProvider{s: rest.PlatformStateUnsealed}
	resp, err := svc.Initialize(unixCaller(0), &rest.BarrierInitRequest{SOPIN: "so", UserPIN: "user"})
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if resp.AdminKeyPEM != "ADMIN-KEY" {
		t.Errorf("the issuing response must carry the key: %+v", resp)
	}
	if svc.issued.key.IsAlive() {
		t.Error("the admin key outlived the unseal")
	}
}

// TestBarrierInitService_ReplayAfterUnsealDestroysAdminKey covers an unseal
// that happened outside /init (for example over /unseal): the next replay
// attempt finds the barrier unsealed, refuses, and wipes the key.
func TestBarrierInitService_ReplayAfterUnsealDestroysAdminKey(t *testing.T) {
	svc, _ := issuingInitService()
	state := &fakeStateProvider{s: rest.PlatformStateUninitialized}
	svc.state = state
	req := &rest.BarrierInitRequest{SOPIN: "so", UserPIN: "user"}
	if _, err := svc.Initialize(unixCaller(0), req); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	state.s = rest.PlatformStateUnsealed
	if _, ok := svc.Replay(unixCaller(0), req); ok {
		t.Error("Replay handed out the bundle after the barrier unsealed")
	}
	if svc.issued.key.IsAlive() {
		t.Error("the admin key outlived the unseal")
	}
}

func TestBarrierInitService_DifferentRequestAfterIssueRejected(t *testing.T) {
	svc, backend := issuingInitService()
	if _, err := svc.Initialize(context.Background(), &rest.BarrierInitRequest{SOPIN: "so", UserPIN: "user"}); err != nil {
		t.Fatalf("first Initialize: %v", err)
	}
	_, err := svc.Initialize(context.Background(), &rest.BarrierInitRequest{SOPIN: "attacker", UserPIN: "user"})
	var issued *rest.ErrInitAlreadyIssued
	if !errors.As(err, &issued) {
		t.Fatalf("expected ErrInitAlreadyIssued, got %v", err)
	}
	if backend.called != 1 {
		t.Errorf("backend called %d times, want 1", backend.called)
	}
}

func TestBarrierInitService_FailedInitIsNotCached(t *testing.T) {
	svc, backend := issuingInitService()
	backend.err = errors.New("mint failed")
	if _, err := svc.Initialize(context.Background(), &rest.BarrierInitRequest{SOPIN: "so", UserPIN: "user"}); err == nil {
		t.Fatal("expected the backend error")
	}
	backend.err = nil
	resp, err := svc.Initialize(context.Background(), &rest.BarrierInitRequest{SOPIN: "so", UserPIN: "user"})
	if err != nil {
		t.Fatalf("retry after failure: %v", err)
	}
	if backend.called != 2 || resp.AdminKeyPEM != "ADMIN-KEY" {
		t.Errorf("retry did not re-run the ceremony: called=%d resp=%+v", backend.called, resp)
	}
}

func TestBarrierInitService_Replay(t *testing.T) {
	svc, _ := issuingInitService()
	req := &rest.BarrierInitRequest{SOPIN: "so", UserPIN: "user"}
	if _, ok := svc.Replay(unixCaller(0), req); ok {
		t.Fatal("nothing issued yet: Replay must not match")
	}
	if _, err := svc.Initialize(unixCaller(0), req); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	resp, ok := svc.Replay(unixCaller(0), &rest.BarrierInitRequest{SOPIN: "so", UserPIN: "user"})
	if !ok || resp.AdminKeyPEM != "ADMIN-KEY" {
		t.Errorf("identical request: ok=%v resp=%+v", ok, resp)
	}
	if _, ok := svc.Replay(unixCaller(0), &rest.BarrierInitRequest{SOPIN: "so", UserPIN: "other"}); ok {
		t.Error("a request with a different PIN must not replay the bundle")
	}
}

// TestInitRequestDigest_FieldBoundaries guards against two requests that
// concatenate to the same bytes digesting equally.
func TestInitRequestDigest_FieldBoundaries(t *testing.T) {
	a := initRequestDigest(&rest.BarrierInitRequest{SOPIN: "ab", UserPIN: "c"})
	b := initRequestDigest(&rest.BarrierInitRequest{SOPIN: "a", UserPIN: "bc"})
	if a == b {
		t.Error("field boundaries are not part of the digest")
	}
	c := initRequestDigest(&rest.BarrierInitRequest{SANs: []string{"x", "y"}})
	d := initRequestDigest(&rest.BarrierInitRequest{SANs: []string{"xy"}})
	if c == d {
		t.Error("SAN boundaries are not part of the digest")
	}
	e := initRequestDigest(&rest.BarrierInitRequest{Officers: []rest.BarrierInitOfficer{{Username: "x", CSRPEM: "y"}}})
	f := initRequestDigest(&rest.BarrierInitRequest{SANs: []string{"x", "y"}})
	if e == f {
		t.Error("officers are indistinguishable from SANs in the digest")
	}
	g := initRequestDigest(&rest.BarrierInitRequest{Officers: []rest.BarrierInitOfficer{{Username: "x", CSRPEM: "csr-1"}}})
	h := initRequestDigest(&rest.BarrierInitRequest{Officers: []rest.BarrierInitOfficer{{Username: "x", CSRPEM: "csr-2"}}})
	if g == h {
		t.Error("an officer's CSR is not part of the digest, so a retry could swap it")
	}
}

// testOfficers returns n officers named officer-1 … officer-n, each with a
// freshly generated CSR the gate's validation accepts.
func testOfficers(t *testing.T, n int) []rest.BarrierInitOfficer {
	t.Helper()
	officers := make([]rest.BarrierInitOfficer, 0, n)
	for i := 1; i <= n; i++ {
		username := "officer-" + strconv.Itoa(i)
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate officer key: %v", err)
		}
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject: pkix.Name{CommonName: username},
		}, key)
		if err != nil {
			t.Fatalf("create officer CSR: %v", err)
		}
		csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
		officers = append(officers, rest.BarrierInitOfficer{Username: username, CSRPEM: string(csrPEM)})
	}
	return officers
}

// withOfficer overwrites officer i's username, and its CSR when csrPEM is
// non-empty, so a table can name one defective officer in an otherwise
// valid set.
func withOfficer(officers []rest.BarrierInitOfficer, i int, username, csrPEM string) []rest.BarrierInitOfficer {
	officers[i].Username = username
	if csrPEM != "" {
		officers[i].CSRPEM = csrPEM
	}
	return officers
}

// TestBarrierInitService_FreshShamirEnrollsOfficersFirst is the fresh
// embedded shamir deployment: an empty officer registry, a barrier sealed by
// the Shamir strategy, and an /init naming one officer per share. The gate
// enrolls every officer with the barrier's share ceremony before
// InitializeShamir, which refuses a set that does not match the share count.
func TestBarrierInitService_FreshShamirEnrollsOfficersFirst(t *testing.T) {
	svc, backend, lifecycle := shamirInitService("shamir")
	resp, err := svc.Initialize(context.Background(), &rest.BarrierInitRequest{
		SOPIN: "so", UserPIN: "user", Threshold: 2, Shares: 3, Officers: testOfficers(t, 3),
	})
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if backend.last.Threshold != "2-of-3" || len(backend.last.Officers) != 3 {
		t.Errorf("ceremony got threshold %q with %d officers, want 2-of-3 with 3",
			backend.last.Threshold, len(backend.last.Officers))
	}
	want := []string{"officer-1", "officer-2", "officer-3"}
	if strings.Join(lifecycle.registered, ",") != strings.Join(want, ",") {
		t.Errorf("barrier officers = %v, want %v", lifecycle.registered, want)
	}
	if lifecycle.shamirCalls != 1 || resp.AdminCertPEM == "" {
		t.Errorf("shamir init did not complete: calls=%d resp=%+v", lifecycle.shamirCalls, resp)
	}
}

// TestBarrierInitService_ShamirRetryCompletesOfficerEnrollment covers an
// identical retry after an attempt that enrolled only part of the set: the
// officers already enrolled are skipped rather than re-registered.
func TestBarrierInitService_ShamirRetryCompletesOfficerEnrollment(t *testing.T) {
	svc, _, lifecycle := shamirInitService("shamir")
	lifecycle.registered = []string{"officer-1"}
	_, err := svc.Initialize(context.Background(), &rest.BarrierInitRequest{
		UserPIN: "user", Threshold: 2, Shares: 3, Officers: testOfficers(t, 3),
	})
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if len(lifecycle.registered) != 3 || lifecycle.shamirCalls != 1 {
		t.Errorf("retry left officers %v and %d shamir calls, want 3 officers and 1 call",
			lifecycle.registered, lifecycle.shamirCalls)
	}
}

// TestBarrierInitService_OfficerEnrollmentFailureFailsInit keeps an SDK
// enrollment failure from reaching InitializeShamir, and reports it as the
// barrier step failing rather than as the SDK's share-count refusal.
func TestBarrierInitService_OfficerEnrollmentFailureFailsInit(t *testing.T) {
	cause := errors.New("ceremony CA not initialized")
	cases := map[string]func(*fakeBarrierLifecycle){
		"register": func(l *fakeBarrierLifecycle) { l.registerErr = cause },
		"list":     func(l *fakeBarrierLifecycle) { l.officersErr = cause },
	}
	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			svc, _, lifecycle := shamirInitService("shamir")
			breakIt(lifecycle)
			_, err := svc.Initialize(context.Background(), &rest.BarrierInitRequest{
				UserPIN: "user", Threshold: 2, Shares: 3, Officers: testOfficers(t, 3),
			})
			var failed ErrBarrierInitFailed
			if !errors.As(err, &failed) || !errors.Is(err, cause) {
				t.Fatalf("got %v, want ErrBarrierInitFailed wrapping the SDK failure", err)
			}
			if lifecycle.shamirCalls != 0 {
				t.Errorf("InitializeShamir ran %d times without the officer set", lifecycle.shamirCalls)
			}
		})
	}
}

func TestBarrierInitService_InitializesBarrierAndReportsState(t *testing.T) {
	backend := &fakeBackend{
		resp: &apidaemon.CeremonyInitResult{CeremonyID: "c1", SPKIPin: "sha256/pin"},
	}
	gate := &fakeGateBarrier{}
	svc := &barrierInitService{
		backend: backend,
		barrier: gate,
		state:   &barrierStateProvider{barrier: gate},
	}
	resp, err := svc.Initialize(context.Background(), &rest.BarrierInitRequest{SOPIN: "so", UserPIN: "user"})
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if gate.initSecret != "user" {
		t.Errorf("barrier secret: got %q want the user PIN", gate.initSecret)
	}
	if gate.syncCalls != 1 {
		t.Errorf("SyncStatus called %d times, want 1", gate.syncCalls)
	}
	if resp.SPKIPin != "sha256/pin" {
		t.Errorf("SPKIPin: got %q want sha256/pin", resp.SPKIPin)
	}
	if resp.State != rest.PlatformStateUnsealed {
		t.Errorf("State: got %q want unsealed", resp.State)
	}
}

func TestBarrierInitService_BarrierFailureFailsTheRequest(t *testing.T) {
	cause := errors.New("barrier refused")
	backend := &fakeBackend{resp: &apidaemon.CeremonyInitResult{CeremonyID: "c1"}}
	gate := &fakeGateBarrier{initErr: cause}
	svc := &barrierInitService{
		backend: backend,
		barrier: gate,
		state:   &barrierStateProvider{barrier: gate},
	}
	resp, err := svc.Initialize(context.Background(), &rest.BarrierInitRequest{UserPIN: "user"})
	var failed ErrBarrierInitFailed
	if !errors.As(err, &failed) {
		t.Fatalf("got %v, want ErrBarrierInitFailed", err)
	}
	if !errors.Is(err, cause) {
		t.Errorf("ErrBarrierInitFailed must unwrap to the barrier error, got %v", err)
	}
	if resp != nil {
		t.Errorf("expected no response, got %+v", resp)
	}
	if gate.syncCalls != 0 {
		t.Errorf("SyncStatus must not run after a failed init, ran %d times", gate.syncCalls)
	}
}

func TestBarrierInitService_EmptyUserPINRefusedBeforeCeremony(t *testing.T) {
	backend := &fakeBackend{resp: &apidaemon.CeremonyInitResult{}}
	gate := &fakeGateBarrier{}
	svc := &barrierInitService{backend: backend, barrier: gate}
	_, err := svc.Initialize(context.Background(), &rest.BarrierInitRequest{SOPIN: "so"})
	var missing rest.ErrMissingRequiredField
	if !errors.As(err, &missing) || missing.Field != "user_pin" {
		t.Fatalf("got %v, want ErrMissingRequiredField{user_pin}", err)
	}
	if backend.called != 0 {
		t.Errorf("the ceremony must not run without a user PIN, ran %d times", backend.called)
	}
}

func TestBarrierInitService_SyncFailureKeepsCachedState(t *testing.T) {
	backend := &fakeBackend{resp: &apidaemon.CeremonyInitResult{CeremonyID: "c1"}}
	gate := &fakeGateBarrier{syncErr: errors.New("status unavailable")}
	svc := &barrierInitService{
		logger:  logging.NewLogger(0, nil),
		backend: backend,
		barrier: gate,
		state:   &barrierStateProvider{barrier: gate},
	}
	resp, err := svc.Initialize(context.Background(), &rest.BarrierInitRequest{UserPIN: "user"})
	if err != nil {
		t.Fatalf("a failed refresh after a good init must not fail /init: %v", err)
	}
	if gate.syncCalls != 1 {
		t.Errorf("SyncStatus called %d times, want 1", gate.syncCalls)
	}
	if resp.State != rest.PlatformStateUnsealed {
		t.Errorf("State: got %q want the cached unsealed state", resp.State)
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

func TestErrBarrierInitFailed_MessageCarriesCause(t *testing.T) {
	err := ErrBarrierInitFailed{Cause: errors.New("sealed backend")}
	if got := err.Error(); got != "barrier initialization after the ceremony failed: sealed backend" {
		t.Errorf("message: got %q", got)
	}
}

func TestErrBarrierInitFailed_NilCause(t *testing.T) {
	err := ErrBarrierInitFailed{}
	if got := err.Error(); got != "barrier initialization after the ceremony failed" {
		t.Errorf("message: got %q", got)
	}
	if err.Unwrap() != nil {
		t.Error("Unwrap of a nil cause must be nil")
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

func TestBarrierUnsealService_EmptyRequestIsAValidationError(t *testing.T) {
	gate := &fakeGateBarrier{initialized: true, sealed: true}
	svc := &barrierUnsealService{barrier: gate}
	for name, req := range map[string]*rest.BarrierUnsealRequest{
		"nil":   nil,
		"empty": {},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := svc.Unseal(context.Background(), req)
			var missing rest.ErrMissingRequiredField
			if !errors.As(err, &missing) {
				t.Fatalf("got %v, want ErrMissingRequiredField", err)
			}
		})
	}
}

func TestBarrierUnsealService_SecretUnseals(t *testing.T) {
	gate := &fakeGateBarrier{initialized: true, sealed: true}
	svc := &barrierUnsealService{barrier: gate, state: &barrierStateProvider{barrier: gate}}
	resp, err := svc.Unseal(context.Background(), &rest.BarrierUnsealRequest{Secret: "k", Share: "s"})
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if gate.unsealSecret != "k" {
		t.Errorf("secret must win over share: got %q", gate.unsealSecret)
	}
	if resp.Sealed || resp.State != rest.PlatformStateUnsealed {
		t.Errorf("got sealed=%v state=%q, want unsealed", resp.Sealed, resp.State)
	}
}

func TestBarrierUnsealService_SecretErrorBubblesUp(t *testing.T) {
	cause := errors.New("wrong secret")
	gate := &fakeGateBarrier{initialized: true, sealed: true, unsealErr: cause}
	svc := &barrierUnsealService{barrier: gate}
	if _, err := svc.Unseal(context.Background(), &rest.BarrierUnsealRequest{Secret: "k"}); !errors.Is(err, cause) {
		t.Errorf("got %v, want the barrier error", err)
	}
}

func TestBarrierUnsealService_PartialShareReportsUnsealing(t *testing.T) {
	gate := &fakeGateBarrier{
		initialized: true,
		sealed:      true,
		shareResp:   &quicbaassdk.QRDBBarrierUnsealShareResponse{Required: 3, Submitted: 1},
	}
	svc := &barrierUnsealService{barrier: gate, state: &barrierStateProvider{barrier: gate}}
	resp, err := svc.Unseal(context.Background(), &rest.BarrierUnsealRequest{Share: "s1"})
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if !resp.Sealed || resp.SharesProvided != 1 || resp.Required != 3 {
		t.Errorf("progress: got %+v", resp)
	}
	if resp.State != rest.PlatformStateUnsealing {
		t.Errorf("State: got %q want unsealing", resp.State)
	}
}

func TestBarrierUnsealService_ShareErrorBubblesUp(t *testing.T) {
	cause := errors.New("bad share")
	gate := &fakeGateBarrier{initialized: true, sealed: true, shareErr: cause}
	svc := &barrierUnsealService{barrier: gate}
	if _, err := svc.Unseal(context.Background(), &rest.BarrierUnsealRequest{Share: "s1"}); !errors.Is(err, cause) {
		t.Errorf("got %v, want the barrier error", err)
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
// Gate HTTP address
// =============================================================================

// TestDefaultBarrierGateConfig_UsesInitOnlyDefault pins the gate to the
// init-only server's default address, whose port choice is tested in
// pkg/api/daemon against every production transport port.
func TestDefaultBarrierGateConfig_UsesInitOnlyDefault(t *testing.T) {
	if got := defaultBarrierGateConfig().httpAddr; got != apidaemon.DefaultInitOnlyHTTPAddr {
		t.Errorf("defaultBarrierGateConfig().httpAddr = %q, want %q",
			got, apidaemon.DefaultInitOnlyHTTPAddr)
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
	if fake.lastCfg.httpAddr != apidaemon.DefaultInitOnlyHTTPAddr {
		t.Errorf("gate httpAddr = %q, want default %q",
			fake.lastCfg.httpAddr, apidaemon.DefaultInitOnlyHTTPAddr)
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
