// Package cluster (directory clusterstub) is a dispatch-check fixture: the
// stub NewClusterGRPCService the server registers. Its package name differs
// from its directory, so the qualifier resolves only through the package
// clause.
package cluster

import (
	"context"

	"example.test/dispatch/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type ClusterGRPCService struct {
	gen.UnimplementedClusterServiceServer
}

func NewClusterGRPCService() *ClusterGRPCService {
	return &ClusterGRPCService{}
}

func (s *ClusterGRPCService) notImplemented(method string) error {
	return status.Errorf(codes.Unimplemented, "cluster: %s not implemented", method)
}

func (s *ClusterGRPCService) Join(ctx context.Context, req *gen.Empty) (*gen.Empty, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "nil request")
	}
	return nil, s.notImplemented("Join") // stub: producer
}

func (s *ClusterGRPCService) Status(ctx context.Context, req *gen.Empty) (*gen.Empty, error) {
	return &gen.Empty{}, nil
}
