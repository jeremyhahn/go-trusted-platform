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

package quicbaas

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// EmbeddedServer manages the lifecycle of an embedded QuicBaaS server.
// It encapsulates the server management logic and provides the service
// interface for use with the SDK-based Client.
//
// Usage:
//
//	srv, err := NewEmbeddedServer(config, logger)
//	if err != nil { ... }
//	if err := srv.Start(ctx); err != nil { ... }
//	defer srv.Stop(ctx)
//
//	// Get the service interface for the SDK client
//	svc := srv.Service()
//	client.StartWithService(ctx, svc)
type EmbeddedServer struct {
	config *Config
	logger *logging.Logger
	server *quicbaassdk.Server

	// activeCA holds the currently-installed external CA. It is read by
	// the ceremony CA adapter on every call so the qrdb embedded transport
	// can be wired before the platform CA is loaded and start dispatching
	// the moment SetCA installs the live CA. Storing through an
	// atomic.Pointer keeps the access lock-free for the ceremony hot path.
	activeCA atomic.Pointer[xkmssdk.TrustedCA]

	// ceremonyCA is the lazy CeremonyCA the SDK wires into the qrdb
	// embedded transport via WithEmbeddedQRDB. It reads activeCA on every
	// call, so SetCA's atomic swap is visible to in-flight ceremony
	// operations without further synchronization.
	ceremonyCA *CeremonyCAAdapter

	// danePublisher is the lazy DANE TLSA publisher the SDK wires into the
	// QuicBaaS server via WithDANEPublisher. It resolves the live platform
	// DNS-backed publisher on every call so the embedded server can be wired
	// before the platform DNS service is initialized. Security().Trust().
	// PublishDANE dispatches through it.
	danePublisher *DANEPublisherAdapter

	started atomic.Bool
	closed  atomic.Bool
	mu      sync.RWMutex
}

// NewEmbeddedServer creates a new embedded QuicBaaS server manager.
// The server is not started until Start() is called.
func NewEmbeddedServer(config *Config, logger *logging.Logger) (*EmbeddedServer, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	srv := &EmbeddedServer{
		config: config,
		logger: logger,
	}
	srv.ceremonyCA = NewCeremonyCAAdapter(srv.loadActiveCA)
	srv.danePublisher = NewDANEPublisherAdapter(nil)
	return srv, nil
}

// NewEmbeddedServerWithCA creates a new embedded QuicBaaS server manager
// with an external Certificate Authority. When provided, the CA is forwarded
// to the QuicBaaS server via WithCA, causing the server to skip its internal
// CA bootstrap and use the given CA for TLS certificate operations.
// The CA must have already been initialized (Load or Init called) before
// being passed here.
func NewEmbeddedServerWithCA(config *Config, logger *logging.Logger, ca xkmssdk.TrustedCA) (*EmbeddedServer, error) {
	srv, err := NewEmbeddedServer(config, logger)
	if err != nil {
		return nil, err
	}
	if ca != nil {
		srv.storeActiveCA(ca)
	}
	return srv, nil
}

// Start initializes and starts the embedded QuicBaaS server.
// This method blocks until the server is ready to accept requests.
// If an external CA was provided via NewEmbeddedServerWithCA, it is
// forwarded to the QuicBaaS server as a ServerOption.
func (s *EmbeddedServer) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.started.Load() {
		return nil
	}
	if s.closed.Load() {
		return ErrServerClosed{}
	}

	// Convert to QuicBaaS native config
	dbConfig := s.config.ToQuicBaaSConfig()

	// Log configuration for debugging
	s.logger.Debug("QuicBaaS embedded server config",
		"storage_backend", dbConfig.Storage.Backend,
		"kms_enabled", dbConfig.KMS.Enabled,
		"kms_backend", dbConfig.KMS.Backend)

	// Build server options
	var serverOpts []quicbaassdk.ServerOption
	if externalCA := s.loadActiveCA(); externalCA != nil {
		serverOpts = append(serverOpts, quicbaassdk.WithCA(externalCA))
		s.logger.Debug("QuicBaaS embedded server using external CA")
	}
	if s.danePublisher != nil {
		serverOpts = append(serverOpts, quicbaassdk.WithDANEPublisher(s.danePublisher))
		s.logger.Debug("QuicBaaS embedded server using DANE publisher")
	}

	// Create the server with options
	srv, err := quicbaassdk.NewServer(dbConfig, serverOpts...)
	if err != nil {
		return ErrConnectionFailed{Cause: err}
	}
	s.server = srv

	// Start the server in embedded mode
	if err := srv.Start(); err != nil {
		return ErrConnectionFailed{Cause: err}
	}

	// Wait for server to be ready
	if err := s.waitForReady(ctx); err != nil {
		// Cleanup on failure
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
		return err
	}

	// Verify service is available
	if srv.Service() == nil {
		return ErrServerNotStarted{}
	}

	s.started.Store(true)
	s.logger.Debug("QuicBaaS embedded server started")
	return nil
}

// waitForReady waits for the server to be fully started and ready to serve requests.
func (s *EmbeddedServer) waitForReady(ctx context.Context) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	timeout := time.After(s.config.RequestTimeout * 3)

	for {
		select {
		case <-ctx.Done():
			return ErrTimeout{Operation: "start"}
		case <-timeout:
			return ErrTimeout{Operation: "start"}
		case <-ticker.C:
			if s.server.IsStarted() {
				return nil
			}
		}
	}
}

// Stop gracefully shuts down the embedded QuicBaaS server.
func (s *EmbeddedServer) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed.Load() {
		return nil
	}
	if !s.started.Load() {
		s.closed.Store(true)
		return nil
	}

	if s.server != nil {
		if err := s.server.Shutdown(ctx); err != nil {
			s.logger.Warn("QuicBaaS embedded server shutdown error", "error", err)
		}
	}

	s.started.Store(false)
	s.closed.Store(true)
	s.logger.Debug("QuicBaaS embedded server stopped")
	return nil
}

// Service returns the QuicBaaS service interface.
// Returns nil if the server is not started.
func (s *EmbeddedServer) Service() service.QuicBaaS {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.started.Load() || s.server == nil {
		return nil
	}
	return s.server.Service()
}

// IsStarted returns true if the server has been started.
func (s *EmbeddedServer) IsStarted() bool {
	return s.started.Load()
}

// IsClosed returns true if the server has been closed.
func (s *EmbeddedServer) IsClosed() bool {
	return s.closed.Load()
}

// Server returns the underlying QuicBaaS server.
// This is primarily useful for testing and advanced operations.
// Returns nil if the server is not started.
func (s *EmbeddedServer) Server() *quicbaassdk.Server {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.started.Load() {
		return nil
	}
	return s.server
}

// CeremonyCA returns the lazy CeremonyCA adapter used by the SDK's qrdb
// embedded transport. The adapter resolves the live platform CA on every
// call so it can be wired before SetCA installs the CA. Returns nil only
// when the embedded server failed to construct.
func (s *EmbeddedServer) CeremonyCA() *CeremonyCAAdapter {
	if s == nil {
		return nil
	}
	return s.ceremonyCA
}

// DANEPublisher returns the lazy DANE publisher adapter registered with the
// QuicBaaS server. The platform installs the live DNS-backed backend via the
// adapter's SetBackend once the DNS service is available. Returns nil only when
// the embedded server failed to construct.
func (s *EmbeddedServer) DANEPublisher() *DANEPublisherAdapter {
	if s == nil {
		return nil
	}
	return s.danePublisher
}

// SetCA replaces the Certificate Authority used by the running embedded
// QuicBaaS server. The swap is atomic: in-flight certificate operations
// complete against the previous CA before the new one takes effect. The
// adapter returned by CeremonyCA() also picks up the new CA atomically so
// subsequent ceremony operations use the swapped-in CA without further
// configuration. Returns ErrServerNotStarted when the server has not been
// started, or the error returned by the underlying server's UpdateCA
// (e.g. when TLS is disabled). Passing nil is a no-op.
func (s *EmbeddedServer) SetCA(ca xkmssdk.TrustedCA) error {
	if ca == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.started.Load() || s.server == nil {
		return ErrServerNotStarted{}
	}
	// Surface the CA to the ceremony adapter FIRST so that
	// Security().Ceremony().Initialize() always sees the latest CA, even
	// when the QuicBaaS CertificateService swap fails (e.g. TLS is
	// disabled). The adapter is independent of the CertificateService —
	// it backs the M6 gate's ceremony bootstrap, which the operator must
	// be able to drive even on a transport-less server.
	s.storeActiveCA(ca)
	// Best-effort UpdateCA: errors are surfaced to the caller but the
	// ceremony adapter still picks up the new CA above.
	if err := s.server.UpdateCA(ca); err != nil {
		return err
	}
	return nil
}

// loadActiveCA returns the currently-installed external CA, or nil when
// none has been set.
func (s *EmbeddedServer) loadActiveCA() xkmssdk.TrustedCA {
	if s == nil {
		return nil
	}
	ptr := s.activeCA.Load()
	if ptr == nil {
		return nil
	}
	return *ptr
}

// storeActiveCA atomically installs the supplied CA as the active one.
// Passing nil clears the stored CA so the adapter reports
// ErrCeremonyCANotAvailable.
func (s *EmbeddedServer) storeActiveCA(ca xkmssdk.TrustedCA) {
	if ca == nil {
		s.activeCA.Store(nil)
		return
	}
	s.activeCA.Store(&ca)
}
