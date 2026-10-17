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
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
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

// requireSystemScopeCaller admits a caller of the KMS REST routes only in the
// system scope: one bound to no tenant, or to the system tenant. The routes
// forward the request context to the embedded SDK, whose KMS and secrets
// services pick their namespace from the go-quicbaas IAM tenant in that
// context, and an absent one selects the system namespace. The SDK re-exports
// no setter for that tenant (go-quicbaas pkg/iam/tenant_context.go:43 is not
// under quicbaas/sdk/go, and the embedded transport's Request,
// sdk/go/transport/embedded/transport.go:414, does not translate
// sdk/go/transport.ContextWithTenant into it), so a tenant-bound caller would
// read and write the system namespace. It is refused instead.
func requireSystemScopeCaller(systemTenantID string, caller *platformtoken.AuthorizedContext) error {
	if caller == nil || caller.TenantID == "" || tenant.IsSystemTenant(systemTenantID, caller.TenantID) {
		return nil
	}
	return ErrKMSRESTTenantBound{TenantID: caller.TenantID}
}

// ErrKMSRESTTenantBound refuses a tenant-bound caller on the daemon KMS REST
// routes, which can serve only the system scope (see requireSystemScopeCaller).
type ErrKMSRESTTenantBound struct {
	TenantID string
}

// Error implements the error interface.
func (e ErrKMSRESTTenantBound) Error() string {
	return "kms: tenant " + e.TenantID + " callers are refused on the KMS REST routes: " +
		"the SDK cannot scope the request to the tenant, so it would run in the system namespace"
}
