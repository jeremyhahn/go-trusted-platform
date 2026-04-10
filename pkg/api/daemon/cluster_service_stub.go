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

//go:build !cluster

package daemon

import (
	"context"
	"log/slog"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"google.golang.org/grpc"
)

// ClusterService is a stub when cluster support is not enabled.
// Build with -tags cluster to enable cluster functionality.
type ClusterService struct{}

// NewClusterService returns an error when cluster support is not enabled.
func NewClusterService(application *app.App, logger *slog.Logger) (*ClusterService, error) {
	return nil, ErrInvalidConfig{Reason: "cluster service not enabled (build with -tags cluster)"}
}

// RegisterGRPCServices is a no-op when cluster support is not enabled.
func (s *ClusterService) RegisterGRPCServices(server *grpc.Server) error {
	return ErrInvalidConfig{Reason: "cluster service not enabled"}
}

// Start is a no-op when cluster support is not enabled.
func (s *ClusterService) Start(ctx context.Context) error {
	return nil
}

// Stop is a no-op when cluster support is not enabled.
func (s *ClusterService) Stop(ctx context.Context) error {
	return nil
}

// IsRunning returns false when cluster support is not enabled.
func (s *ClusterService) IsRunning() bool {
	return false
}

// Name returns the service name.
func (s *ClusterService) Name() string {
	return "cluster"
}

// Bootstrap returns an error when cluster support is not enabled.
func (s *ClusterService) Bootstrap(ctx context.Context) error {
	return ErrInvalidConfig{Reason: "cluster service not enabled"}
}

// Join returns an error when cluster support is not enabled.
func (s *ClusterService) Join(ctx context.Context, addresses []string) error {
	return ErrInvalidConfig{Reason: "cluster service not enabled"}
}

// Leave returns an error when cluster support is not enabled.
func (s *ClusterService) Leave(ctx context.Context) error {
	return ErrInvalidConfig{Reason: "cluster service not enabled"}
}

// Status returns nil when cluster support is not enabled.
func (s *ClusterService) Status(ctx context.Context) (interface{}, error) {
	return nil, ErrInvalidConfig{Reason: "cluster service not enabled"}
}

// Nodes returns nil when cluster support is not enabled.
func (s *ClusterService) Nodes(ctx context.Context) (interface{}, error) {
	return nil, ErrInvalidConfig{Reason: "cluster service not enabled"}
}

// IsLeader returns false when cluster support is not enabled.
func (s *ClusterService) IsLeader() bool {
	return false
}

// GetLeader returns nil when cluster support is not enabled.
func (s *ClusterService) GetLeader(ctx context.Context) (interface{}, error) {
	return nil, ErrInvalidConfig{Reason: "cluster service not enabled"}
}

// WaitForLeader returns an error when cluster support is not enabled.
func (s *ClusterService) WaitForLeader(ctx context.Context) (interface{}, error) {
	return nil, ErrInvalidConfig{Reason: "cluster service not enabled"}
}

// IsHealthy returns false when cluster support is not enabled.
func (s *ClusterService) IsHealthy() bool {
	return false
}

// HealthCheck returns an error when cluster support is not enabled.
func (s *ClusterService) HealthCheck(ctx context.Context) error {
	return ErrInvalidConfig{Reason: "cluster service not enabled"}
}

// NodeID returns 0 when cluster support is not enabled.
func (s *ClusterService) NodeID() uint64 {
	return 0
}

// Config returns nil when cluster support is not enabled.
func (s *ClusterService) Config() interface{} {
	return nil
}

// Coordinator returns nil when cluster support is not enabled.
func (s *ClusterService) Coordinator() interface{} {
	return nil
}
