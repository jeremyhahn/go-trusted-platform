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

package daemon

import (
	"context"
	"log/slog"
	"sync/atomic"

	"google.golang.org/grpc"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
)

// tenantComponentsGetter is the interface that the QuicBaaS service must implement
// to provide tenant management components. This interface is implemented by quicBaaS
// when built with the iam build tag.
type tenantComponentsGetter interface {
	GetTenantManager(ctx context.Context) (quicbaassdk.IAMDomainTenantManager, error)
}

// TenantService wraps the QuicBaaS IAM TenantManager for platformd.
// It provides tenant lifecycle operations including:
//   - Tenant creation, retrieval, update, and deletion
//   - Tenant listing with pagination
//   - Per-tenant DEK provisioning and deprovisioning
//
// Note: Platform-specific orchestration (VLAN allocation, OVS bridge setup,
// quota management) is handled separately by the platform layer when needed.
type TenantService struct {
	app           *app.App
	logger        *slog.Logger
	tenantManager quicbaassdk.IAMDomainTenantManager
	sdkClient     quicbaassdk.Client
	grpcServer    *TenantGRPCServer
	running       atomic.Bool
}

// NewTenantService creates a new tenant service that wraps QuicBaaS's TenantManager.
// Returns an error if the app doesn't have QuicBaaS configured or IAM tenant
// management is not available.
func NewTenantService(application *app.App, logger *slog.Logger) (*TenantService, error) {
	if application == nil {
		return nil, ErrInvalidConfig{Reason: "application is required for tenant service"}
	}

	// Check if QuicBaaS backend is available
	factory, ok := application.DAOFactory().(*quicbaas.Factory)
	if !ok {
		return nil, ErrInvalidConfig{Reason: "QuicBaaS backend not available for tenant service"}
	}

	client := factory.Client()
	if client == nil || !client.IsStarted() {
		return nil, ErrInvalidConfig{Reason: "QuicBaaS client not started"}
	}

	dbSvc := client.Service()
	if dbSvc == nil {
		return nil, ErrInvalidConfig{Reason: "QuicBaaS service not available"}
	}

	// Check if the service supports tenant management (built with iam tag)
	if _, ok := dbSvc.(tenantComponentsGetter); !ok {
		return nil, ErrInvalidConfig{Reason: "QuicBaaS service does not support tenant management (build with -tags iam)"}
	}

	// Obtain the SDK client for ClusterDEK operations
	sdk := factory.SDK()
	if sdk == nil {
		return nil, ErrInvalidConfig{Reason: "QuicBaaS SDK client not available"}
	}

	return &TenantService{
		app:       application,
		logger:    logger,
		sdkClient: sdk,
	}, nil
}

// RegisterGRPCServices registers tenant-related gRPC services with a gRPC server.
// The tenant service uses the IAM TenantManager from QuicBaaS for tenant CRUD operations.
func (s *TenantService) RegisterGRPCServices(server *grpc.Server) error {
	if server == nil {
		return ErrInvalidConfig{Reason: "gRPC server is required"}
	}

	// Get the QuicBaaS factory from app
	factory, ok := s.app.DAOFactory().(*quicbaas.Factory)
	if !ok {
		return ErrInvalidConfig{Reason: "datastore is not QuicBaaS"}
	}

	client := factory.Client()
	if client == nil || !client.IsStarted() {
		return ErrInvalidConfig{Reason: "QuicBaaS client not started"}
	}

	dbSvc := client.Service()
	if dbSvc == nil {
		return ErrInvalidConfig{Reason: "QuicBaaS service not available"}
	}

	// Type assert to tenant components getter interface
	tenantSvc, ok := dbSvc.(tenantComponentsGetter)
	if !ok {
		return ErrInvalidConfig{Reason: "QuicBaaS service does not support tenant management"}
	}

	// Get the IAM tenant manager from QuicBaaS service
	ctx := context.Background()
	tenantMgr, err := tenantSvc.GetTenantManager(ctx)
	if err != nil || tenantMgr == nil {
		return ErrInvalidConfig{Reason: "tenant manager not available"}
	}

	s.tenantManager = tenantMgr

	// Create and register the gRPC server
	// Note: The gRPC server is registered without a platform tenant manager.
	// Methods that require the platform tenant manager will return FailedPrecondition
	// until SetManager is called. This allows the gRPC service to be registered
	// even when the full platform orchestration is not yet configured.
	s.grpcServer = NewTenantGRPCServer(WithTenantLogger(s.logger))
	platformv1.RegisterTenantServiceServer(server, s.grpcServer)

	s.logger.Info("Tenant gRPC service registered",
		slog.Bool("tenant_manager_ready", s.tenantManager != nil),
	)

	return nil
}

// Start starts the tenant service.
func (s *TenantService) Start(ctx context.Context) error {
	if s.running.Load() {
		return nil
	}

	s.running.Store(true)
	s.logger.Info("Tenant service started")
	return nil
}

// Stop stops the tenant service.
func (s *TenantService) Stop(ctx context.Context) error {
	if !s.running.Load() {
		return nil
	}

	s.running.Store(false)
	s.logger.Info("Tenant service stopped")
	return nil
}

// IsRunning returns whether the tenant service is running.
func (s *TenantService) IsRunning() bool {
	return s.running.Load()
}

// Name returns the service name.
func (s *TenantService) Name() string {
	return "tenant"
}

// TenantManager returns the QuicBaaS IAM TenantManager for direct access.
// This allows other services to interact with tenant operations.
func (s *TenantService) TenantManager() quicbaassdk.IAMDomainTenantManager {
	return s.tenantManager
}
