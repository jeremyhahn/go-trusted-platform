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

// serve_barrier_gate.go implements milestone M6 from
// docs/08-bootstrap-auth-architecture.md: gate the remote transport
// listeners (gRPC TCP, REST, QUIC, MCP) on barrier unseal state. Only the
// Unix socket and a minimal /healthz + /init + /unseal HTTP endpoint are
// allowed before the barrier is unsealed.

package commands

import (
	"context"
	"time"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"

	apidaemon "github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	appbackends "github.com/jeremyhahn/go-trusted-platform/pkg/app/backends"
	"github.com/jeremyhahn/go-trusted-platform/pkg/barrier"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// =============================================================================
// Typed errors
// =============================================================================

// ErrBarrierGateRequiresApp is returned when the barrier gate is invoked
// without an initialized App.
type ErrBarrierGateRequiresApp struct{}

// Error returns a human-readable description of the error.
func (ErrBarrierGateRequiresApp) Error() string {
	return "barrier gate requires an initialized app"
}

// ErrBarrierGateRequiresSDK is returned when the barrier gate is invoked
// without a quicbaas SDK client.
type ErrBarrierGateRequiresSDK struct{}

// Error returns a human-readable description of the error.
func (ErrBarrierGateRequiresSDK) Error() string {
	return "barrier gate requires a quicbaas SDK client"
}

// ErrBarrierInitFailed is returned by /init when the bootstrap ceremony
// succeeded but the barrier could not be initialized.
type ErrBarrierInitFailed struct {
	Cause error
}

// Error returns a human-readable description of the error.
func (e ErrBarrierInitFailed) Error() string {
	if e.Cause == nil {
		return "barrier initialization after the ceremony failed"
	}
	return "barrier initialization after the ceremony failed: " + e.Cause.Error()
}

// Unwrap returns the underlying barrier error.
func (e ErrBarrierInitFailed) Unwrap() error {
	return e.Cause
}

// =============================================================================
// Barrier seam
// =============================================================================

// gateBarrier is the part of *barrier.Manager the gate services drive.
type gateBarrier interface {
	Initialize(ctx context.Context, secret string) error
	SyncStatus(ctx context.Context) error
	Unseal(ctx context.Context, secret string) error
	UnsealWithShare(ctx context.Context, share string) (*quicbaassdk.QRDBBarrierUnsealShareResponse, error)
	IsInitialized() bool
	IsSealed() bool
	IsUnsealing() bool
}

// Compile-time assertion that the manager satisfies the gate seam.
var _ gateBarrier = (*barrier.Manager)(nil)

// gateBarrierOf returns the app's barrier manager, or nil when the app has
// none. A nil *barrier.Manager must not become a non-nil interface value.
func gateBarrierOf(a *app.App) gateBarrier {
	if a == nil {
		return nil
	}
	mgr := a.Barrier()
	if mgr == nil {
		return nil
	}
	return mgr
}

// =============================================================================
// State provider
// =============================================================================

// barrierStateProvider implements rest.PlatformStateProvider by reading the
// platform's barrier manager. The state machine has four observable values:
//   - uninitialized: barrier never initialized
//   - sealed:        initialized but locked
//   - unsealing:     sealed, with at least one Shamir share accepted
//   - unsealed:      operational
//
// The provider is safe for concurrent use; the underlying barrier.Manager
// uses atomics for its cached flags.
type barrierStateProvider struct {
	barrier gateBarrier
}

// State returns the current platform state.
func (p *barrierStateProvider) State(_ context.Context) rest.PlatformState {
	if p == nil || p.barrier == nil {
		return rest.PlatformStateUninitialized
	}
	if !p.barrier.IsInitialized() {
		return rest.PlatformStateUninitialized
	}
	if p.barrier.IsUnsealing() {
		return rest.PlatformStateUnsealing
	}
	if p.barrier.IsSealed() {
		return rest.PlatformStateSealed
	}
	return rest.PlatformStateUnsealed
}

// =============================================================================
// Init service (POST /init)
// =============================================================================

// barrierInitService implements rest.BarrierInitService by delegating to the
// QuicBaaS ceremony backend (which terminates at go-qrdb's CeremonyService).
// On success the backend response is rendered into a rest.BarrierInitResponse
// and the barrier is initialized; a barrier failure fails the request.
type barrierInitService struct {
	logger  *logging.Logger
	backend apidaemon.CeremonyBackend
	barrier gateBarrier
	state   rest.PlatformStateProvider
}

// Initialize delegates the canonical ceremony bootstrap to the configured
// backend, then initializes the barrier. The state in the response reflects
// the barrier state after both steps.
func (s *barrierInitService) Initialize(ctx context.Context, req *rest.BarrierInitRequest) (*rest.BarrierInitResponse, error) {
	if s == nil || s.backend == nil {
		return nil, &rest.ErrBarrierInitServiceUnavailable{}
	}
	if req == nil {
		req = &rest.BarrierInitRequest{}
	}
	// The user PIN is the barrier secret. Refuse an empty one before the
	// ceremony runs, so a request that cannot initialize the barrier
	// leaves nothing half done.
	if s.barrier != nil && req.UserPIN == "" {
		return nil, rest.ErrMissingRequiredField{Field: "user_pin"}
	}
	thresholdSpec := ""
	if req.Shares > 0 || req.Threshold > 0 {
		thresholdSpec = formatThreshold(req.Threshold, req.Shares)
	}

	// The qrdb embedded ceremony transport threads the per-request
	// SOPin/UserPin from the ceremony-initialize request directly into the
	// service layer, so the PINs are supplied on the call itself below.
	out, err := s.backend.Initialize(ctx, &apidaemon.CeremonyInitRequest{
		SOPIN:                  req.SOPIN,
		UserPIN:                req.UserPIN,
		Threshold:              thresholdSpec,
		Hostname:               req.Hostname,
		SANs:                   req.SANs,
		CredentialSealStrategy: req.CredentialSealStrategy,
	})
	if err != nil {
		return nil, err
	}
	resp := &rest.BarrierInitResponse{}
	if out != nil {
		resp.CeremonyID = out.CeremonyID
		resp.InitializedAt = out.InitializedAt
		resp.SPKIPin = out.SPKIPin
	}
	if s.barrier != nil {
		// The qrdb ceremony service does not initialize the data-plane
		// StorageBarrier as a side effect — it only stores PINs in the
		// credential service and transitions its own state machine. We
		// must explicitly drive Manager.Initialize so the BarrierServicer
		// (which the M6 waitForUnseal loop polls via SDK.Security().
		// Barrier().BarrierStatus) reports initialized + unsealed and the
		// gate releases.
		if err := s.barrier.Initialize(ctx, req.UserPIN); err != nil {
			return nil, ErrBarrierInitFailed{Cause: err}
		}
		// Refresh the cached flags from the backend. Initialize has already
		// set them, so a failed refresh leaves a correct state to report.
		if err := s.barrier.SyncStatus(ctx); err != nil && s.logger != nil {
			s.logger.Warn("barrier status refresh after init failed; reporting the cached state",
				"error", err.Error())
		}
	}
	if s.state != nil {
		resp.State = s.state.State(ctx)
	}
	return resp, nil
}

// =============================================================================
// Unseal service (POST /unseal)
// =============================================================================

// barrierUnsealService implements rest.BarrierUnsealService by delegating to
// the platform's barrier.Manager. Either Secret (single-key) or Share
// (Shamir, multi-step) must be provided; the manager tracks quorum progress
// internally.
type barrierUnsealService struct {
	barrier gateBarrier
	state   rest.PlatformStateProvider
}

// Unseal submits a single secret or share toward the unseal threshold.
func (s *barrierUnsealService) Unseal(ctx context.Context, req *rest.BarrierUnsealRequest) (*rest.BarrierUnsealResponse, error) {
	if s == nil || s.barrier == nil {
		return nil, &rest.ErrBarrierUnsealServiceUnavailable{}
	}
	if req == nil || (req.Secret == "" && req.Share == "") {
		return nil, rest.ErrMissingRequiredField{Field: "secret or share"}
	}
	resp := &rest.BarrierUnsealResponse{}
	switch {
	case req.Secret != "":
		if err := s.barrier.Unseal(ctx, req.Secret); err != nil {
			return nil, err
		}
		resp.Sealed = false
	case req.Share != "":
		shareResp, err := s.barrier.UnsealWithShare(ctx, req.Share)
		if err != nil {
			return nil, err
		}
		if shareResp != nil {
			resp.Sealed = !shareResp.Complete
			resp.SharesProvided = shareResp.Submitted
			resp.Required = shareResp.Required
		}
	}
	if s.state != nil {
		resp.State = s.state.State(ctx)
	}
	return resp, nil
}

// =============================================================================
// Init-only mode runner
// =============================================================================

// barrierGateConfig captures the dependencies required to run the
// init-only mode listener and the unseal-wait loop.
type barrierGateConfig struct {
	socketPath string
	httpAddr   string
	pollEvery  time.Duration
}

// defaultBarrierGateConfig returns sensible defaults aligned with the
// canonical port assignments documented in CLAUDE.md.
func defaultBarrierGateConfig() barrierGateConfig {
	return barrierGateConfig{
		socketPath: "/run/platformd.sock",
		httpAddr:   apidaemon.DefaultInitOnlyHTTPAddr,
		pollEvery:  time.Second,
	}
}

// initOnlyGate is the function invoked by the daemon entry points to run
// the M6 barrier-unseal gate. Production code points it at
// runInitOnlyMode; tests substitute a fake to assert the gate is invoked
// in both runWithWebservices and runDaemonOnly without standing up an
// actual listener.
var initOnlyGate = runInitOnlyMode

// invokeBarrierGate is the single call site used by both runWithWebservices
// and runDaemonOnly to run the M6 init-only mode gate. It builds the gate
// config from the package-level CLI flags (so the gate binds the same
// Unix socket path the production daemon will reuse) and dispatches via
// the initOnlyGate hook. Returning early from the caller on a non-nil
// error keeps production listeners gated until the barrier is unsealed.
func invokeBarrierGate(ctx context.Context, a *app.App, logger *logging.Logger) error {
	gateCfg := defaultBarrierGateConfig()
	gateCfg.socketPath = serveSocketPath
	return initOnlyGate(ctx, a, logger, gateCfg)
}

// runInitOnlyMode binds the Unix socket and a 127.0.0.1 loopback HTTP
// listener that serves only /healthz + /init + /unseal. The function
// blocks until the barrier transitions to unsealed (state machine reports
// sealed=false, initialized=true) or ctx is cancelled. Once the barrier
// is unsealed the listeners are torn down so the caller can bind the
// production transports.
//
// This is the M6 gate: remote transports are NOT bound while this runs.
func runInitOnlyMode(ctx context.Context, a *app.App, logger *logging.Logger, gateCfg barrierGateConfig) error {
	if a == nil {
		return ErrBarrierGateRequiresApp{}
	}

	gate := gateBarrierOf(a)
	stateProvider := &barrierStateProvider{barrier: gate}

	// Wire init service when the SDK client is available. When the SDK
	// client is missing we still start the listener so /healthz works,
	// but /init returns 503 ErrBarrierInitServiceUnavailable.
	var initSvc rest.BarrierInitService
	if sdk := a.QuicBaaSSDKClient(); sdk != nil {
		initSvc = &barrierInitService{
			logger:  logger,
			backend: appbackends.NewCeremonyBackend(logger, sdk),
			barrier: gate,
			state:   stateProvider,
		}
	}

	// Wire unseal service when the barrier manager is available. The
	// manager is always present once App.initBarrier() returned ok, but
	// we tolerate its absence so the gate can also surface a useful
	// /healthz when the platform is misconfigured.
	var unsealSvc rest.BarrierUnsealService
	if gate != nil {
		unsealSvc = &barrierUnsealService{
			barrier: gate,
			state:   stateProvider,
		}
	}

	srv, err := apidaemon.NewInitOnlyServer(apidaemon.InitOnlyConfig{
		SocketPath:     gateCfg.socketPath,
		HTTPListenAddr: gateCfg.httpAddr,
		State:          stateProvider,
		Init:           initSvc,
		Unseal:         unsealSvc,
		Logger:         logger,
	})
	if err != nil {
		return err
	}
	if err := srv.Start(ctx); err != nil {
		return err
	}
	logger.Info("init-only mode bound; remote transports gated until barrier unseal",
		"unix_socket", gateCfg.socketPath,
		"http_loopback", srv.HTTPListenAddr())

	// Block until the barrier reaches the unsealed state, the context is
	// cancelled, or the initial state was already unsealed.
	waitErr := waitForUnseal(ctx, a, logger, gateCfg.pollEvery)

	// Always tear down the init-only listeners regardless of the wait
	// outcome; the caller will either return (on cancel/error) or bind
	// the production transports next.
	if stopErr := srv.Stop(ctx); stopErr != nil {
		logger.Warn("init-only mode shutdown returned error", "error", stopErr.Error())
	}
	if waitErr != nil {
		return waitErr
	}
	logger.Info("barrier unsealed; init-only mode released, production transports may bind now")
	return nil
}

// waitForUnseal blocks until the barrier reports unsealed (initialized=true,
// sealed=false), or ctx is cancelled. It races the manager's WaitReady
// signal (instant for local unseals) against a polling ticker (catches
// /init transitioning us from uninitialized to sealed, plus external
// unseals from peer nodes that the local manager only learns about via
// SyncStatus). No time.Sleep is used.
func waitForUnseal(ctx context.Context, a *app.App, logger *logging.Logger, pollEvery time.Duration) error {
	if a == nil {
		return ErrBarrierGateRequiresApp{}
	}
	mgr := a.Barrier()
	if mgr == nil {
		// No manager: nothing to wait for. Treat as ready.
		return nil
	}
	if !mgr.IsSealed() && mgr.IsInitialized() {
		// Already unsealed.
		return nil
	}

	if pollEvery <= 0 {
		pollEvery = time.Second
	}

	// Run WaitReady in a goroutine so we can multiplex its completion
	// with the polling ticker via select. WaitReady's own context guards
	// goroutine lifetime so cancellation propagates correctly.
	readyCtx, cancelReady := context.WithCancel(ctx)
	defer cancelReady()
	readyCh := make(chan struct{}, 1)
	go func() {
		if err := mgr.WaitReady(readyCtx); err == nil {
			select {
			case readyCh <- struct{}{}:
			default:
			}
		}
	}()

	ticker := time.NewTicker(pollEvery)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-readyCh:
			// Successful local unseal — manager closed its ready channel.
			return nil
		case <-ticker.C:
			if syncErr := mgr.SyncStatus(ctx); syncErr != nil {
				logger.Debug("waitForUnseal: SyncStatus failed; will retry",
					"error", syncErr.Error())
				continue
			}
			if mgr.IsInitialized() && !mgr.IsSealed() {
				return nil
			}
		}
	}
}

// =============================================================================
// helpers
// =============================================================================

// formatThreshold renders a Shamir threshold pair into the "M-of-N" string
// expected by the CeremonyService Threshold field.
func formatThreshold(threshold, shares int) string {
	if threshold <= 0 || shares <= 0 {
		return ""
	}
	return formatInt(threshold) + "-of-" + formatInt(shares)
}

// formatInt is a small allocation-free integer formatter for the
// Shamir threshold rendering. Avoids pulling in fmt for a hot path
// that runs once per /init.
func formatInt(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
