// Package server is a dispatch-check fixture: it registers the stub cluster
// service and builds the real one for something else.
package server

import (
	realcluster "example.test/dispatch/clusterreal"
	"example.test/dispatch/clusterstub"
	"example.test/dispatch/gen"
	"google.golang.org/grpc"
)

func Register(srv *grpc.Server) {
	svc := cluster.NewClusterGRPCService()
	gen.RegisterClusterServiceServer(srv, svc)
}

func Standby() *realcluster.ClusterGRPCService {
	return realcluster.NewClusterGRPCService()
}
