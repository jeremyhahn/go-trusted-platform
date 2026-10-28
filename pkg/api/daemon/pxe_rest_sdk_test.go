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

//go:build codec_msgpack

package daemon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	iammw "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	pxerest "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/pxe"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkrest "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
)

// scopedPlatformToken is the platform-token validator for a caller holding
// scopes: whatever token it presents resolves to them.
type scopedPlatformToken struct {
	scopes []string
}

func (v scopedPlatformToken) Validate(context.Context, string, string, string, string) (*platformtoken.AuthorizedContext, error) {
	return &platformtoken.AuthorizedContext{Subject: "pxe-operator", Scopes: v.scopes}, nil
}

// connectPXEREST serves the PXE webservice as the daemon mounts it — the
// operator routes behind the platform-token middleware and the scope each
// RPC takes on gRPC, the enabled install webhook beside them — over TLS, and
// returns an SDK REST connection to it for a caller holding scopes (#975).
func connectPXEREST(t *testing.T, server platformv1.PXEServiceServer, scopes ...string) grpc.ClientConnInterface {
	t.Helper()
	logger := logging.DefaultLogger()
	writer := response.NewResponseWriter(logger, nil)
	tokens, err := iammw.NewPlatformTokenMiddleware(logger, writer, scopedPlatformToken{scopes: scopes},
		iammw.PlatformTokenConfig{AllowBearer: true})
	require.NoError(t, err)

	pxe := pxerest.NewPXERouter(logger, server, writer, true)
	pxe.SetScopeAuthorizer(tokens)
	operator := mux.NewRouter()
	pxe.RegisterRoutes(operator.PathPrefix("/api/v1").Subrouter())
	machine := mux.NewRouter()
	pxe.RegisterMachineFacingRoutes(machine.PathPrefix("/api/v1").Subrouter())

	routes := http.NewServeMux()
	routes.HandleFunc("GET /health/live", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	routes.Handle("POST /api/v1/pxe/webhook/complete", machine)
	routes.Handle("/", tokens.Handler(operator))

	bundle := testutil.GenerateTestTLSBundle(t)
	srv := httptest.NewUnstartedServer(routes)
	srv.TLS = bundle.ServerTLSConfig()
	srv.StartTLS()
	t.Cleanup(srv.Close)
	adapter, err := sdkrest.Connect(context.Background(), platform.NewOptions(
		platform.WithRESTAddr(srv.URL),
		platform.WithTLSConfig(bundle.ClientTLSConfig()),
		platform.WithBearerToken("operator-token"),
	))
	return connection(t, adapter, err)
}

// TestSDKREST_PXEMethods drives every PXEService RPC through the SDK's REST
// transport and requires the reply and the call the service received to be
// the ones gRPC gives (#975).
func TestSDKREST_PXEMethods(t *testing.T) {
	testSDKPXEMethods(t, "REST", connectPXEREST)
}

// TestSDKREST_PXEMethodsRefuse requires REST to refuse a caller without the
// scope before the service is reached, and to return NotFound for a device
// the service does not have, as gRPC does.
func TestSDKREST_PXEMethodsRefuse(t *testing.T) {
	testSDKPXERefusesScope(t, "REST", connectPXEREST)
	testSDKPXERefusesNotFound(t, "REST", connectPXEREST)
}
