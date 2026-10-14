// Package badserver is a dispatch-check fixture: a registration whose
// implementation comes from outside the module, so its type is unknown.
package badserver

import (
	"example.org/external/factory"
	"example.test/dispatch/gen"
	"google.golang.org/grpc"
)

func Register(srv *grpc.Server) {
	gen.RegisterClusterServiceServer(srv, factory.Build()) // unresolved: impl
}
