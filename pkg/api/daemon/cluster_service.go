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

//go:build cluster

package daemon

import (
	"context"
	"log/slog"
	"sync/atomic"

	"google.golang.org/grpc"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cluster"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
)

// clusterComponentsGetter is the interface that the QuicBaaS service must implement
// to provide cluster coordination components. This interface is implemented by QuicBaaS
// when built with the cluster build tag.
type clusterComponentsGetter interface {
	GetClusterCoordinator(ctx context.Context) (cluster.Coordinator, error)
}

// ClusterService wraps the cluster.Coordinator for platformd daemon integration.
// It provides cluster lifecycle operations including:
//   - Bootstrap: Initialize a new cluster with this node as the first member
//   - Join: Join an existing cluster by connecting to peer nodes
//   - Leave: Gracefully leave the cluster
//   - Status: Get current cluster status including leader, term, and quorum state
//   - Nodes: List all nodes in the cluster
//
// The service integrates with QuicBaaS's Raft capabilities through the cluster.Coordinator
// interface, providing consensus-based distributed state management.
type ClusterService struct {
	app         *app.App
	logger      *slog.Logger
	coordinator cluster.Coordinator
	running     atomic.Bool
}

// NewClusterService creates a new cluster service that wraps the cluster.Coordinator.
// Returns an error if the app doesn't have QuicBaaS configured or cluster coordination
// is not available.
// Kept with no caller: the cluster registration lane wires it to clear the ClusterService stubs (docs/cluster/engineering.md).
func NewClusterService(application *app.App, logger *slog.Logger) (*ClusterService, error) {
	if application == nil {
		return nil, ErrInvalidConfig{Reason: "application is required for cluster service"}
	}

	if logger == nil {
		return nil, ErrInvalidConfig{Reason: "logger is required for cluster service"}
	}

	// Check if QuicBaaS backend is available
	factory, ok := application.DAOFactory().(*quicbaas.Factory)
	if !ok {
		return nil, ErrInvalidConfig{Reason: "QuicBaaS backend not available for cluster service"}
	}

	client := factory.Client()
	if client == nil || !client.IsStarted() {
		return nil, ErrInvalidConfig{Reason: "QuicBaaS client not started"}
	}

	dbSvc := client.Service()
	if dbSvc == nil {
		return nil, ErrInvalidConfig{Reason: "QuicBaaS service not available"}
	}

	// Check if the service supports cluster coordination (built with cluster tag)
	if _, ok := dbSvc.(clusterComponentsGetter); !ok {
		return nil, ErrInvalidConfig{Reason: "QuicBaaS service does not support cluster coordination (build with -tags cluster)"}
	}

	return &ClusterService{
		app:    application,
		logger: logger,
	}, nil
}

// RegisterGRPCServices registers cluster-related gRPC services with a gRPC server.
// The cluster service obtains its coordinator from the QuicBaaS service.
func (s *ClusterService) RegisterGRPCServices(server *grpc.Server) error {
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

	// Type assert to cluster components getter interface
	clusterSvc, ok := dbSvc.(clusterComponentsGetter)
	if !ok {
		return ErrInvalidConfig{Reason: "QuicBaaS service does not support cluster coordination"}
	}

	// Get the coordinator from QuicBaaS service
	ctx := context.Background()
	coordinator, err := clusterSvc.GetClusterCoordinator(ctx)
	if err != nil {
		return ErrInvalidConfig{Reason: "failed to get cluster coordinator: " + err.Error()}
	}

	if coordinator == nil {
		return ErrInvalidConfig{Reason: "cluster coordinator not available"}
	}

	s.coordinator = coordinator

	s.logger.Info("Cluster service initialized",
		slog.Bool("coordinator_ready", s.coordinator != nil),
		slog.Uint64("node_id", s.coordinator.NodeID()),
	)

	return nil
}

// Start starts the cluster service and the underlying coordinator.
func (s *ClusterService) Start(ctx context.Context) error {
	if s.running.Load() {
		return nil
	}

	if s.coordinator == nil {
		return ErrServiceNotRunning{ServiceName: "cluster"}
	}

	// Start the coordinator if it's not already running
	if !s.coordinator.IsRunning() {
		if err := s.coordinator.Start(ctx); err != nil {
			s.logger.Error("Failed to start cluster coordinator",
				slog.String("error", err.Error()),
			)
			return ErrProvisionFailed{Reason: "failed to start cluster coordinator: " + err.Error()}
		}
	}

	s.running.Store(true)
	s.logger.Info("Cluster service started",
		slog.Uint64("node_id", s.coordinator.NodeID()),
	)
	return nil
}

// Stop stops the cluster service and the underlying coordinator.
func (s *ClusterService) Stop(ctx context.Context) error {
	if !s.running.Load() {
		return nil
	}

	if s.coordinator != nil && s.coordinator.IsRunning() {
		if err := s.coordinator.Stop(ctx); err != nil {
			s.logger.Error("Failed to stop cluster coordinator",
				slog.String("error", err.Error()),
			)
			return ErrShutdownFailed{Reason: "failed to stop cluster coordinator: " + err.Error()}
		}
	}

	s.running.Store(false)
	s.logger.Info("Cluster service stopped")
	return nil
}

// IsRunning returns whether the cluster service is running.
func (s *ClusterService) IsRunning() bool {
	return s.running.Load()
}

// Name returns the service name.
func (s *ClusterService) Name() string {
	return "cluster"
}

// Bootstrap initializes a new cluster with this node as the first member.
// This should only be called once on the first node in a new cluster.
// Subsequent nodes should use Join to connect to the existing cluster.
func (s *ClusterService) Bootstrap(ctx context.Context) error {
	if !s.running.Load() {
		return ErrServiceNotRunning{ServiceName: "cluster"}
	}

	if s.coordinator == nil {
		return ErrServiceNotRunning{ServiceName: "cluster"}
	}

	s.logger.Info("Bootstrapping cluster",
		slog.Uint64("node_id", s.coordinator.NodeID()),
	)

	if err := s.coordinator.Bootstrap(ctx); err != nil {
		s.logger.Error("Failed to bootstrap cluster",
			slog.String("error", err.Error()),
		)
		return ErrProvisionFailed{Reason: "cluster bootstrap failed: " + err.Error()}
	}

	s.logger.Info("Cluster bootstrapped successfully",
		slog.Uint64("node_id", s.coordinator.NodeID()),
	)

	return nil
}

// Join adds this node to an existing cluster by connecting to the specified peer addresses.
// At least one address must be provided. The addresses should point to existing cluster members.
func (s *ClusterService) Join(ctx context.Context, addresses []string) error {
	if !s.running.Load() {
		return ErrServiceNotRunning{ServiceName: "cluster"}
	}

	if s.coordinator == nil {
		return ErrServiceNotRunning{ServiceName: "cluster"}
	}

	if len(addresses) == 0 {
		return ErrInvalidConfig{Reason: "at least one peer address is required to join cluster"}
	}

	s.logger.Info("Joining cluster",
		slog.Uint64("node_id", s.coordinator.NodeID()),
		slog.Any("addresses", addresses),
	)

	if err := s.coordinator.Join(ctx, addresses); err != nil {
		s.logger.Error("Failed to join cluster",
			slog.String("error", err.Error()),
			slog.Any("addresses", addresses),
		)
		return ErrProvisionFailed{Reason: "cluster join failed: " + err.Error()}
	}

	s.logger.Info("Joined cluster successfully",
		slog.Uint64("node_id", s.coordinator.NodeID()),
	)

	return nil
}

// Leave gracefully removes this node from the cluster.
// This transfers leadership if this node is the leader and notifies other nodes.
func (s *ClusterService) Leave(ctx context.Context) error {
	if !s.running.Load() {
		return ErrServiceNotRunning{ServiceName: "cluster"}
	}

	if s.coordinator == nil {
		return ErrServiceNotRunning{ServiceName: "cluster"}
	}

	s.logger.Info("Leaving cluster",
		slog.Uint64("node_id", s.coordinator.NodeID()),
	)

	if err := s.coordinator.Leave(ctx); err != nil {
		s.logger.Error("Failed to leave cluster",
			slog.String("error", err.Error()),
		)
		return ErrShutdownFailed{Reason: "cluster leave failed: " + err.Error()}
	}

	s.logger.Info("Left cluster successfully",
		slog.Uint64("node_id", s.coordinator.NodeID()),
	)

	return nil
}

// Status returns the current cluster status including state, node count, leader info,
// term number, and quorum status.
func (s *ClusterService) Status(ctx context.Context) (*cluster.ClusterStatus, error) {
	if !s.running.Load() {
		return nil, ErrServiceNotRunning{ServiceName: "cluster"}
	}

	if s.coordinator == nil {
		return nil, ErrServiceNotRunning{ServiceName: "cluster"}
	}

	status, err := s.coordinator.Status(ctx)
	if err != nil {
		s.logger.Error("Failed to get cluster status",
			slog.String("error", err.Error()),
		)
		return nil, err
	}

	return status, nil
}

// Nodes returns all nodes in the cluster with their current state information.
func (s *ClusterService) Nodes(ctx context.Context) (cluster.NodeList, error) {
	if !s.running.Load() {
		return cluster.NodeList{}, ErrServiceNotRunning{ServiceName: "cluster"}
	}

	if s.coordinator == nil {
		return cluster.NodeList{}, ErrServiceNotRunning{ServiceName: "cluster"}
	}

	nodes, err := s.coordinator.Nodes(ctx)
	if err != nil {
		s.logger.Error("Failed to get cluster nodes",
			slog.String("error", err.Error()),
		)
		return cluster.NodeList{}, err
	}

	return nodes, nil
}

// IsLeader returns true if this node is the current cluster leader.
func (s *ClusterService) IsLeader() bool {
	if !s.running.Load() || s.coordinator == nil {
		return false
	}
	return s.coordinator.IsLeader()
}

// GetLeader returns information about the current cluster leader.
func (s *ClusterService) GetLeader(ctx context.Context) (*cluster.Node, error) {
	if !s.running.Load() {
		return nil, ErrServiceNotRunning{ServiceName: "cluster"}
	}

	if s.coordinator == nil {
		return nil, ErrServiceNotRunning{ServiceName: "cluster"}
	}

	return s.coordinator.GetLeader(ctx)
}

// WaitForLeader blocks until a leader is elected or the context is cancelled.
func (s *ClusterService) WaitForLeader(ctx context.Context) (*cluster.Node, error) {
	if !s.running.Load() {
		return nil, ErrServiceNotRunning{ServiceName: "cluster"}
	}

	if s.coordinator == nil {
		return nil, ErrServiceNotRunning{ServiceName: "cluster"}
	}

	return s.coordinator.WaitForLeader(ctx)
}

// IsHealthy returns true if the cluster is in a healthy state with quorum.
func (s *ClusterService) IsHealthy() bool {
	if !s.running.Load() || s.coordinator == nil {
		return false
	}
	return s.coordinator.IsHealthy()
}

// HealthCheck performs a health check on the cluster and returns any errors.
func (s *ClusterService) HealthCheck(ctx context.Context) error {
	if !s.running.Load() {
		return ErrServiceNotRunning{ServiceName: "cluster"}
	}

	if s.coordinator == nil {
		return ErrServiceNotRunning{ServiceName: "cluster"}
	}

	return s.coordinator.HealthCheck(ctx)
}

// NodeID returns this node's unique identifier in the cluster.
func (s *ClusterService) NodeID() uint64 {
	if s.coordinator == nil {
		return 0
	}
	return s.coordinator.NodeID()
}

// Config returns the cluster configuration.
func (s *ClusterService) Config() *cluster.Config {
	if s.coordinator == nil {
		return nil
	}
	return s.coordinator.Config()
}

// Coordinator returns the underlying cluster coordinator for direct access.
// This allows other services to interact with cluster operations.
func (s *ClusterService) Coordinator() cluster.Coordinator {
	return s.coordinator
}
