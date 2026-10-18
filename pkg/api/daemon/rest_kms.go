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

package daemon

import (
	"net/http"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	restkms "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/kms"

	cryptoclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/crypto"
	dekclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/dek"
	kmsclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"
	secretsclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/secrets"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
)

// kmsRESTPrefix is where the daemon mounts the KMS routes.
const kmsRESTPrefix = restBasePath + restkms.BasePath

// KMSRESTClients are the QuicBaaS SDK clients the KMS REST routes call: the
// same clients the KMS gRPC, QUIC, MCP and embedded transports call, so a
// key, DEK or secret made over one transport is the one every other sees.
type KMSRESTClients struct {
	KMS     kmsclient.Client
	Crypto  cryptoclient.Client
	DEK     dekclient.Client
	Secrets secretsclient.Client
	// SystemTenantID is the platform's system tenant, the only tenant a
	// caller of these routes may be bound to (requireSystemScopeCaller).
	SystemTenantID string
}

// SetKMSHandlers mounts the KMS routes (docs/kms/api.md) on the daemon's
// REST router. The handlers are the webservice's (pkg/webservice/v1/rest/kms),
// so both listeners speak one wire format, the one the SDK REST client calls.
// Each route requires the scope its go-quicbaas KMS RPC requires on gRPC,
// checked by the daemon's REST guard (docs/kms/api.md §6).
func (s *RESTServer) SetKMSHandlers(clients KMSRESTClients, guard *restapi.ScopeGuard) {
	logger := logging.NewFromSlog(s.logger)
	respWriter := response.NewResponseWriter(logger, nil)
	router := restkms.NewKMSRouter(logger, clients.KMS, clients.Crypto, clients.DEK, clients.Secrets, respWriter)
	sub := s.router.PathPrefix(kmsRESTPrefix).Subrouter()
	// Match on the encoded path so a secret or DEK path with slashes, sent as
	// %2F, stays one {name}/{path} segment; the handlers unescape it
	// (restkms.KMSRouter.RegisterRoutes).
	sub.UseEncodedPath()
	for _, route := range router.Routes() {
		scope := grpcapi.ScopeForMethod(route.RPC)
		handler := route.Handler
		sub.HandleFunc(route.Path, guard.RequireCaller(scope,
			func(w http.ResponseWriter, r *http.Request, caller *platformtoken.AuthorizedContext) {
				if err := requireSystemScopeCaller(clients.SystemTenantID, caller); err != nil {
					respWriter.Error403(w, r, err, nil)
					return
				}
				handler(w, r)
			})).Methods(route.Method)
	}
	s.logger.Info("KMS REST routes registered")
}
