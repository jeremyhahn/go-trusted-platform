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
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"

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
	config     *Config
	logger     *logging.Logger
	server     *quicbaassdk.Server
	externalCA xkmssdk.XKMSCA // optional; forwarded to server as WithCA option

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

	return &EmbeddedServer{
		config: config,
		logger: logger,
	}, nil
}

// NewEmbeddedServerWithCA creates a new embedded QuicBaaS server manager
// with an external Certificate Authority. When provided, the CA is forwarded
// to the QuicBaaS server via WithCA, causing the server to skip its internal
// CA bootstrap and use the given CA for TLS certificate operations.
// The CA must have already been initialized (Load or Init called) before
// being passed here.
func NewEmbeddedServerWithCA(config *Config, logger *logging.Logger, ca xkmssdk.XKMSCA) (*EmbeddedServer, error) {
	srv, err := NewEmbeddedServer(config, logger)
	if err != nil {
		return nil, err
	}
	srv.externalCA = ca
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
	if s.externalCA != nil {
		serverOpts = append(serverOpts, quicbaassdk.WithCA(s.externalCA))
		s.logger.Debug("QuicBaaS embedded server using external CA")
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
