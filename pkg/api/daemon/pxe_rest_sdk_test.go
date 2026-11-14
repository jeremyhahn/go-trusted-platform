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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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
//
// pxeRESTWebhookSecret is the install-completion webhook HMAC key the
// REST test server configures (pxe.ServiceConfig.WebhookSecret, #240).
const pxeRESTWebhookSecret = "sdk-rest-test-webhook-secret"

// connectPXEREST connects the SDK REST transport with the webhook key the
// test server verifies, so WebhookComplete is signed by the real client.
func connectPXEREST(t *testing.T, server platformv1.PXEServiceServer, scopes ...string) grpc.ClientConnInterface {
	t.Helper()
	return connectPXERESTKeyed(t, server, []byte(pxeRESTWebhookSecret), scopes...)
}

// connectPXERESTKeyed serves the PXE routes (the webhook verifying
// pxeRESTWebhookSecret) and connects the SDK REST transport signing
// webhook reports with key; a nil key sends them unsigned.
func connectPXERESTKeyed(t *testing.T, server platformv1.PXEServiceServer, key []byte, scopes ...string) grpc.ClientConnInterface {
	t.Helper()
	logger := logging.DefaultLogger()
	writer := response.NewResponseWriter(logger, nil)
	tokens, err := iammw.NewPlatformTokenMiddleware(logger, writer, scopedPlatformToken{scopes: scopes},
		iammw.PlatformTokenConfig{AllowBearer: true})
	require.NoError(t, err)

	pxe := pxerest.NewPXERouter(logger, server, writer, true)
	pxe.SetScopeAuthorizer(tokens)
	pxe.SetWebhookSecret(pxeRESTWebhookSecret)
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
		platform.WithPXEWebhookKey(key),
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

// TestSDKREST_PXEWebhookNeedsClientKey pins that the signature comes from
// the client: a REST connection with no webhook key, or the wrong one, is
// refused 401 (Unauthenticated) and the service never sees the report.
func TestSDKREST_PXEWebhookNeedsClientKey(t *testing.T) {
	const method = "/platform.v1.PXEService/WebhookComplete"
	req := pxeSDKRequests()[method]
	for name, key := range map[string][]byte{"no key": nil, "wrong key": []byte("not-the-secret")} {
		t.Run(name, func(t *testing.T) {
			via := newPXESDKFixture()
			untouched := via.svc.recorded()
			conn := connectPXERESTKeyed(t, via.server, key, "*:*")
			err := conn.Invoke(context.Background(), method, req, &platformv1.PXEWebhookCompleteResponse{})
			require.Equal(t, codes.Unauthenticated, status.Code(err), "%v", err)
			require.Equal(t, untouched, via.svc.recorded())
		})
	}
}
