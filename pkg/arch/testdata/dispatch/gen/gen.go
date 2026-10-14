// Package gen is a dispatch-check fixture: a generated gRPC service.
package gen

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Empty struct{}

type ClusterServiceServer interface {
	Join(context.Context, *Empty) (*Empty, error)
	Leave(context.Context, *Empty) (*Empty, error)
	Status(context.Context, *Empty) (*Empty, error)
	mustEmbedUnimplementedClusterServiceServer()
}

type UnimplementedClusterServiceServer struct{}

func (UnimplementedClusterServiceServer) Join(context.Context, *Empty) (*Empty, error) {
	return nil, status.Error(codes.Unimplemented, "method Join not implemented")
}

func (UnimplementedClusterServiceServer) Leave(context.Context, *Empty) (*Empty, error) { // stub: embedded
	return nil, status.Error(codes.Unimplemented, "method Leave not implemented")
}

func (UnimplementedClusterServiceServer) Status(context.Context, *Empty) (*Empty, error) {
	return nil, status.Error(codes.Unimplemented, "method Status not implemented")
}

func (UnimplementedClusterServiceServer) mustEmbedUnimplementedClusterServiceServer() {}

func RegisterClusterServiceServer(s *grpc.Server, srv ClusterServiceServer) {
	s.RegisterService(nil, srv)
}
