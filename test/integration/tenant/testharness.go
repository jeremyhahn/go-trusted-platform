//go:build integration

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

package tenant

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"google.golang.org/grpc"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/transport"
	grpctransport "github.com/jeremyhahn/go-quicbaas/sdk/go/transport/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

const (
	// testQuicBaaSPort is the fixed port for QuicBaaS gRPC in tests
	testQuicBaaSPort = 50100
	// testPlatformPort is the fixed port for Platform Tenant gRPC in tests
	testPlatformPort = 50101
)

// TestHarness provides an isolated test environment with embedded QuicBaaS
// and gRPC server for tenant integration testing.
type TestHarness struct {
	mu            sync.Mutex
	dataDir       string
	grpcListener  net.Listener
	grpcServer    *grpc.Server
	quicBaaS      *quicbaas.Server
	grpcTransport *grpctransport.Transport
	tenantManager *tenant.Manager
	logger        *logging.Logger
	grpcAddr      string
	started       bool
}

// TestHarnessConfig contains configuration for the test harness
type TestHarnessConfig struct {
	DataDir  string
	LogLevel slog.Level
}

// DefaultTestHarnessConfig returns default configuration for the test harness
func DefaultTestHarnessConfig() *TestHarnessConfig {
	return &TestHarnessConfig{
		DataDir:  filepath.Join(os.TempDir(), fmt.Sprintf("tenant-test-%d", time.Now().UnixNano())),
		LogLevel: slog.LevelWarn,
	}
}

// NewTestHarness creates a new test harness with the given configuration.
// If config is nil, default configuration is used.
func NewTestHarness(config *TestHarnessConfig) (*TestHarness, error) {
	if config == nil {
		config = DefaultTestHarnessConfig()
	}

	logger := logging.NewLogger(config.LogLevel, nil)

	return &TestHarness{
		dataDir: config.DataDir,
		logger:  logger,
	}, nil
}

// Start starts the test harness with embedded QuicBaaS and gRPC server.
func (h *TestHarness) Start(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.started {
		return nil
	}

	// Create data directory
	if err := os.MkdirAll(h.dataDir, 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	// Create QuicBaaS configuration with gRPC enabled for IAM access
	// NOTE: IAM is enabled via the 'iam' build tag, not configuration
	quicbaasConfig := &quicbaas.ServerFullConfig{
		Server: quicbaas.ServerNodeConfig{
			Host:              "127.0.0.1",
			Embedded:          false, // Need network listeners for gRPC
			ReadTimeout:       5 * time.Second,
			WriteTimeout:      5 * time.Second,
			IdleTimeout:       60 * time.Second,
			ExposeShardHeader: false,
			Shards:            []uint64{1},
			GRPC: quicbaas.ServerGRPCConfig{
				Enabled: true,
				Port:    testQuicBaaSPort,
			},
			REST: quicbaas.ServerRESTConfig{
				Enabled: false,
			},
			Unix: quicbaas.ServerUnixConfig{
				Enabled: false,
			},
		},
		Raft: quicbaas.RaftConfig{
			NodeID:              1,
			RaftAddress:         "127.0.0.1:50102",
			ElectionRTT:         10,
			HeartbeatRTT:        1,
			RTTMillisecond:      100,
			SnapshotEntries:     10000,
			CompactionOverhead:  1000,
			MaxInMemLogSize:     1024 * 1024,
			MaxSendQueueSize:    1024,
			MaxReceiveQueueSize: 1024,
			MutualTLS:           false,
			EnableBootstrap:     false,
		},
		Storage: quicbaas.StorageConfig{
			Backend:               quicbaas.StorageBackendPebble,
			DataDir:               filepath.Join(h.dataDir, "data"),
			WALDir:                filepath.Join(h.dataDir, "wal"),
			CacheSize:             64 * 1024 * 1024,
			MaxOpenFiles:          1000,
			DisableWAL:            false,
			SyncWrites:            true,
			BytesPerSync:          1024 * 1024,
			MemTableSize:          64 * 1024 * 1024,
			MemTableStopWrites:    8,
			L0CompactionThreshold: 4,
			L0StopWritesThreshold: 12,
			MaxConcurrentReads:    4,
			MaxConcurrentWrites:   4,
		},
		Security: quicbaas.SecurityConfig{
			TLSEnabled:    false,
			TLSCertFile:   "",
			TLSKeyFile:    "",
			TLSCAFile:     "",
			TLSClientAuth: false,
			FIPSMode:      false,
		},
		Logging: quicbaas.LoggingConfig{
			Level:  "warn",
			Format: "json",
			Output: "stdout",
		},
		Discovery: quicbaas.DiscoveryConfig{
			Enabled: false,
		},
		KMS: quicbaas.KMSConfig{
			Enabled: true,
			Backend: quicbaas.KMSBackendSoftware,
		},
	}

	// Create QuicBaaS server
	var err error
	h.quicBaaS, err = quicbaas.NewServer(quicbaasConfig)
	if err != nil {
		return fmt.Errorf("failed to create QuicBaaS server: %w", err)
	}

	// Start QuicBaaS in a goroutine (blocks in non-embedded mode)
	startErrChan := make(chan error, 1)
	go func() {
		if err := h.quicBaaS.Start(); err != nil {
			startErrChan <- err
		}
	}()

	// Wait for QuicBaaS to be ready
	startTimeout := time.After(30 * time.Second)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case err := <-startErrChan:
			return fmt.Errorf("failed to start QuicBaaS: %w", err)
		case <-startTimeout:
			return fmt.Errorf("timeout waiting for QuicBaaS to start")
		case <-ticker.C:
			if h.quicBaaS.IsStarted() {
				goto quicbaasReady
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
quicbaasReady:

	// Small delay for gRPC server to fully accept connections
	time.Sleep(100 * time.Millisecond)

	// Create SDK gRPC transport to QuicBaaS for IAM tenant operations
	quicbaasAddr := fmt.Sprintf("127.0.0.1:%d", testQuicBaaSPort)
	h.grpcTransport, err = grpctransport.New(&transport.Config{
		Address: quicbaasAddr,
		Timeout: 10 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("failed to create gRPC transport to QuicBaaS: %w", err)
	}

	// Create IAM tenant client via SDK transport
	iamTenantClient := iam.NewTenantClient(h.grpcTransport)

	// Create tenant.Manager with SDK IAM client
	tenantConfig := tenant.DefaultConfig()
	tenantConfig.EnableDEKIsolation = false // Disable DEK for testing simplicity

	h.tenantManager, err = tenant.NewManager(&tenant.ManagerConfig{
		IAMTenantClient: iamTenantClient,
		Config:          tenantConfig,
		Logger:          h.logger.Slog(),
	})
	if err != nil {
		return fmt.Errorf("failed to create tenant manager: %w", err)
	}

	// Create gRPC listener for platform tenant service
	h.grpcListener, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", testPlatformPort))
	if err != nil {
		return fmt.Errorf("failed to create gRPC listener: %w", err)
	}
	h.grpcAddr = h.grpcListener.Addr().String()

	// Create gRPC server
	h.grpcServer = grpc.NewServer()

	// Create and register TenantGRPCServer
	tenantGRPCServer := daemon.NewTenantGRPCServer(
		daemon.WithTenantManager(h.tenantManager),
		daemon.WithTenantLogger(h.logger.Slog()),
	)
	platformv1.RegisterTenantServiceServer(h.grpcServer, tenantGRPCServer)

	// Start gRPC server
	go func() {
		if err := h.grpcServer.Serve(h.grpcListener); err != nil {
			h.logger.Slog().Error("gRPC server error", "error", err)
		}
	}()

	h.started = true
	h.logger.Info("Test harness started",
		slog.String("grpc_addr", h.grpcAddr),
		slog.String("data_dir", h.dataDir),
	)

	return nil
}

// Stop stops the test harness and cleans up resources.
func (h *TestHarness) Stop(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.started {
		return nil
	}

	// Stop gRPC server
	if h.grpcServer != nil {
		h.grpcServer.GracefulStop()
	}

	// Close gRPC listener
	if h.grpcListener != nil {
		h.grpcListener.Close()
	}

	// Close SDK gRPC transport
	if h.grpcTransport != nil {
		h.grpcTransport.Close()
	}

	// Stop QuicBaaS
	if h.quicBaaS != nil {
		if err := h.quicBaaS.Shutdown(ctx); err != nil {
			h.logger.Warn("Error stopping QuicBaaS", slog.String("error", err.Error()))
		}
	}

	// Cleanup data directory
	if err := os.RemoveAll(h.dataDir); err != nil {
		h.logger.Warn("Error removing data directory", slog.String("error", err.Error()))
	}

	h.started = false
	h.logger.Info("Test harness stopped")

	return nil
}

// GRPCAddr returns the gRPC server address for the platform tenant service.
func (h *TestHarness) GRPCAddr() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.grpcAddr
}

// IsStarted returns whether the test harness is started.
func (h *TestHarness) IsStarted() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.started
}

// NewGRPCClient creates a new gRPC client connected to the test harness platform service.
func (h *TestHarness) NewGRPCClient(ctx context.Context) (platformv1.TenantServiceClient, *grpc.ClientConn, error) {
	h.mu.Lock()
	addr := h.grpcAddr
	h.mu.Unlock()

	if addr == "" {
		return nil, nil, fmt.Errorf("test harness not started")
	}

	// Use timeout for connection
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(dialCtx, addr,
		helpers.GRPCTransportCredentials(),
		grpc.WithBlock(),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to gRPC server: %w", err)
	}

	return platformv1.NewTenantServiceClient(conn), conn, nil
}

// TenantManager returns the tenant manager for direct testing.
func (h *TestHarness) TenantManager() *tenant.Manager {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.tenantManager
}
