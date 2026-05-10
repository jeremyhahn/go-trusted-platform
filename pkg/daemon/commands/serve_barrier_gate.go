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
	"errors"
	"time"

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

// ErrBarrierUnsealMissingSecret is returned when /unseal is called with no
// secret and no share.
type ErrBarrierUnsealMissingSecret struct{}

// Error returns a human-readable description of the error.
func (ErrBarrierUnsealMissingSecret) Error() string {
	return "unseal request requires either secret or share"
}

// =============================================================================
// State provider
// =============================================================================

// barrierStateProvider implements rest.PlatformStateProvider by reading the
// platform's barrier manager. The state machine has three observable values:
//   - uninitialized: barrier never initialized
//   - sealed:        initialized but locked
//   - unsealed:      operational
//
// The provider is safe for concurrent use; the underlying barrier.Manager
// uses atomics for sealed/initialized booleans.
type barrierStateProvider struct {
	app *app.App
}

// State returns the current platform state.
func (p *barrierStateProvider) State(_ context.Context) rest.PlatformState {
	if p == nil || p.app == nil {
		return rest.PlatformStateUninitialized
	}
	mgr := p.app.Barrier()
	if mgr == nil {
		return rest.PlatformStateUninitialized
	}
	if !mgr.IsInitialized() {
		return rest.PlatformStateUninitialized
	}
	if mgr.IsSealed() {
		return rest.PlatformStateSealed
	}
	return rest.PlatformStateUnsealed
}

// =============================================================================
// Init service (POST /init)
// =============================================================================

// barrierInitService implements rest.BarrierInitService by delegating to the
// QuicBaaS ceremony backend (which terminates at go-qrdb's CeremonyService).
// On success the backend response is rendered into a rest.BarrierInitResponse;
// the platform state will transition to sealed (passphrase/shamir) or unsealed
// (software with auto-unseal) depending on the strategy.
type barrierInitService struct {
	logger  *logging.Logger
	app     *app.App
	backend apidaemon.CeremonyBackend
	state   rest.PlatformStateProvider
}

// Initialize delegates the canonical ceremony bootstrap to the configured
// backend. The state in the response reflects the barrier state at the
// moment the ceremony returns.
func (s *barrierInitService) Initialize(ctx context.Context, req *rest.BarrierInitRequest) (*rest.BarrierInitResponse, error) {
	if s == nil || s.backend == nil {
		return nil, &rest.ErrBarrierInitServiceUnavailable{}
	}
	if req == nil {
		req = &rest.BarrierInitRequest{}
	}
	thresholdSpec := ""
	if req.Shares > 0 || req.Threshold > 0 {
		thresholdSpec = formatThreshold(req.Threshold, req.Shares)
	}
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
	}
	if s.state != nil {
		resp.State = s.state.State(ctx)
	}
	if s.app != nil && s.app.Barrier() != nil {
		// Refresh the barrier manager state from the backend so the next
		// /healthz call sees the updated initialized/sealed flags without
		// waiting for the next external sync.
		_ = s.app.Barrier().SyncStatus(ctx)
		if s.state != nil {
			resp.State = s.state.State(ctx)
		}
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
	logger  *logging.Logger
	app     *app.App
	manager *barrier.Manager
	state   rest.PlatformStateProvider
}

// Unseal submits a single secret or share toward the unseal threshold.
func (s *barrierUnsealService) Unseal(ctx context.Context, req *rest.BarrierUnsealRequest) (*rest.BarrierUnsealResponse, error) {
	if s == nil || s.manager == nil {
		return nil, &rest.ErrBarrierUnsealServiceUnavailable{}
	}
	if req == nil || (req.Secret == "" && req.Share == "") {
		return nil, ErrBarrierUnsealMissingSecret{}
	}
	resp := &rest.BarrierUnsealResponse{}
	switch {
	case req.Secret != "":
		if err := s.manager.Unseal(ctx, req.Secret); err != nil {
			return nil, err
		}
		resp.Sealed = false
	case req.Share != "":
		shareResp, err := s.manager.UnsealWithShare(ctx, req.Share)
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
		httpAddr:   "127.0.0.1:9445",
		pollEvery:  time.Second,
	}
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

	stateProvider := &barrierStateProvider{app: a}

	// Wire init service when the SDK client is available. When the SDK
	// client is missing we still start the listener so /healthz works,
	// but /init returns 503 ErrBarrierInitServiceUnavailable.
	var initSvc rest.BarrierInitService
	if sdk := a.QuicBaaSSDKClient(); sdk != nil {
		backend := appbackends.NewCeremonyBackend(logger, sdk)
		initSvc = &barrierInitService{
			logger:  logger,
			app:     a,
			backend: backend,
			state:   stateProvider,
		}
	}

	// Wire unseal service when the barrier manager is available. The
	// manager is always present once App.initBarrier() returned ok, but
	// we tolerate its absence so the gate can also surface a useful
	// /healthz when the platform is misconfigured.
	var unsealSvc rest.BarrierUnsealService
	if mgr := a.Barrier(); mgr != nil {
		unsealSvc = &barrierUnsealService{
			logger:  logger,
			app:     a,
			manager: mgr,
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

// _ usage keeps the errors import alive when the file is inspected by
// goimports without other err wrapping in this version.
var _ = errors.New
