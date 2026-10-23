// Package clusterreal is a dispatch-check fixture: a real
// NewClusterGRPCService with the same name as the registered stub's.
package clusterreal

import (
	"context"

	"example.test/dispatch/gen"
)

type ClusterGRPCService struct {
	gen.UnimplementedClusterServiceServer
}

func NewClusterGRPCService() *ClusterGRPCService {
	return &ClusterGRPCService{}
}

func (s *ClusterGRPCService) Join(ctx context.Context, req *gen.Empty) (*gen.Empty, error) {
	return &gen.Empty{}, nil
}

func (s *ClusterGRPCService) Leave(ctx context.Context, req *gen.Empty) (*gen.Empty, error) {
	return &gen.Empty{}, nil
}

func (s *ClusterGRPCService) Status(ctx context.Context, req *gen.Empty) (*gen.Empty, error) {
	return &gen.Empty{}, nil
}
