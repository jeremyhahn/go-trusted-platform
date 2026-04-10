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

	"github.com/flynn/noise"
	"github.com/jeremyhahn/go-truststrap/pkg/noiseproto"
	noiseboot "github.com/jeremyhahn/go-truststrap/pkg/noiseproto/bootstrap"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// Server wraps the go-truststrap Noise_NK bootstrap server as a platform
// protocol listener. It serves CA certificate bundles over Noise_NK encrypted
// TCP connections for secure trust bootstrapping without requiring TLS.
type Server struct {
	inner     *noiseboot.Server
	config    *bootstrap.NoiseServerConfig
	logger    *logging.Logger
	staticKey *noise.DHKey
	started   atomic.Bool
}

// NewServer creates a new Noise_NK bootstrap server with the given platform
// configuration, bundle provider, and logger. An ephemeral Curve25519 static
// key is generated for the NK handshake. The public key can be retrieved via
// PublicKey for out-of-band distribution to clients.
func NewServer(
	cfg *bootstrap.NoiseServerConfig,
	bundler noiseboot.BundleProvider,
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

	staticKey, err := noiseproto.GenerateStaticKey()
	if err != nil {
		return nil, &ErrKeyGenerationFailed{Cause: err}
	}

	innerCfg := &noiseboot.ServerConfig{
		ListenAddr:     cfg.ListenAddr,
		StaticKey:      staticKey,
		CABundler:      bundler,
		MaxConnections: cfg.MaxConnections,
		ReadTimeout:    cfg.ReadTimeout,
		WriteTimeout:   cfg.WriteTimeout,
		Logger:         logger.Slog(),
	}

	inner, err := noiseboot.NewServer(innerCfg)
	if err != nil {
		return nil, &ErrServerStartFailed{Cause: err}
	}

	return &Server{
		inner:     inner,
		config:    cfg,
		logger:    logger,
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
