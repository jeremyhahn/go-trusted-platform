//go:build iam && codec_msgpack

package daemon

import (
	"context"
	"net/http"

	"google.golang.org/grpc"

	"github.com/jeremyhahn/go-trusted-platform/pkg/util/peercred"
)

// operatorGRPCServerOption stamps the in-process operator's credentials on
// every call a test gRPC server takes, as embedded_host does for its
// embedder, so a fixture that serves over TCP still has an identified local
// caller (SPEC row 109 refuses one with no identity at all). It carries the
// build constraint of its only user, iam_mcp_parity_test.go.
func operatorGRPCServerOption() grpc.ServerOption {
	return grpc.ChainUnaryInterceptor(func(ctx context.Context, req interface{}, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		return handler(peercred.ContextWithProcessCredentials(ctx), req)
	})
}

// operatorHTTPHandler does the same for a test MCP or REST bridge served
// over httptest.
func operatorHTTPHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(peercred.ContextWithProcessCredentials(r.Context())))
	})
}
