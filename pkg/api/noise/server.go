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

package noise

import (
	"context"
	"net"
	"sync/atomic"

	noiseboot "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/trust/bootstrap"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// Server wraps the stack's canonical Noise_NK bootstrap server (composed by
// go-xkms, reached through the QuicBaaS SDK) as a platform protocol listener.
// It serves CA certificate bundles over Noise_NK encrypted TCP connections
// for secure trust bootstrapping without requiring TLS.
type Server struct {
	inner     *noiseboot.NoiseServer
	config    *bootstrap.NoiseServerConfig
	logger    *logging.Logger
	staticKey *noiseboot.NoiseStaticKey
	started   atomic.Bool
}

// NewServer creates a new Noise_NK bootstrap server with the given platform
// configuration, bundle provider, and logger. An ephemeral Curve25519 static
// key is generated for the NK handshake. The public key can be retrieved via
// PublicKey for out-of-band distribution to clients.
func NewServer(
	cfg *bootstrap.NoiseServerConfig,
	bundler noiseboot.NoiseBundleProvider,
	logger *logging.Logger,
) (*Server, error) {

	if cfg == nil {
		return nil, &ErrNilConfig{}
	}
	if bundler == nil {
		return nil, &ErrNilBundleProvider{}
	}
	if logger == nil {
		return nil, &ErrNilLogger{}
	}

	staticKey, err := noiseboot.GenerateNoiseStaticKey()
	if err != nil {
		return nil, &ErrKeyGenerationFailed{Cause: err}
	}
	// Since go-truststrap v0.2.0-alpha the generator returns a protected
	// StaticKey whose private scalar lives outside the Go heap; the embedded
	// noise.DHKey is what the server config and the SDK's NoiseStaticKey
	// alias still take. The protected pair is ephemeral and lives for the
	// server's lifetime, matching the previous behavior.
	dhKey := &staticKey.DHKey

	innerCfg := &noiseboot.NoiseServerConfig{
		ListenAddr:     cfg.ListenAddr,
		StaticKey:      dhKey,
		CABundler:      bundler,
		MaxConnections: cfg.MaxConnections,
		ReadTimeout:    cfg.ReadTimeout,
		WriteTimeout:   cfg.WriteTimeout,
		Logger:         logger.Slog(),
	}

	inner, err := noiseboot.NewNoiseServer(innerCfg)
	if err != nil {
		return nil, &ErrServerStartFailed{Cause: err}
	}

	return &Server{
		inner:  inner,
		config: cfg,
		logger: logger,
		// The server keeps the NoiseStaticKey — private scalar in protected
		// memory — and hands only its embedded DHKey to the inner config above.
		// Under SDK 0.3.0 NoiseStaticKey aliased noise.DHKey, so assigning the
		// DHKey here compiled by accident; 0.6.0 makes it a distinct type and
		// refuses, which is correct.
		staticKey: staticKey,
	}, nil
}

// Start begins listening for incoming Noise_NK connections. It returns
// ErrServerAlreadyStarted if the server is already running.
func (s *Server) Start(ctx context.Context) error {
	if !s.started.CompareAndSwap(false, true) {
		return &ErrServerAlreadyStarted{}
	}

	if err := s.inner.Start(); err != nil {
		s.started.Store(false)
		return &ErrServerStartFailed{Cause: err}
	}

	s.logger.Info("noise bootstrap server started",
		"addr", s.inner.Addr().String())

	return nil
}

// Stop gracefully shuts down the server. It returns ErrServerNotStarted if
// the server is not running.
func (s *Server) Stop(ctx context.Context) error {
	if !s.started.Load() {
		return &ErrServerNotStarted{}
	}

	if err := s.inner.Stop(ctx); err != nil {
		return &ErrServerStopFailed{Cause: err}
	}

	s.started.Store(false)

	s.logger.Info("noise bootstrap server stopped")

	return nil
}

// Addr returns the listener's network address. This is useful when the server
// is started on an OS-assigned port (":0") for testing. It returns nil if
// the server has not been started.
func (s *Server) Addr() net.Addr {
	return s.inner.Addr()
}

// PublicKey returns the server's Curve25519 static public key as raw bytes.
// Clients need this key (distributed out-of-band) to complete the NK handshake.
func (s *Server) PublicKey() []byte {
	return s.staticKey.Public
}

// IsRunning reports whether the server is currently accepting connections.
func (s *Server) IsRunning() bool {
	return s.started.Load()
}
