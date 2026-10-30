package daemon

import (
	"net/http"
	"strings"

	cryptoclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/crypto"
	dekclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/dek"
	kmsclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"
	secretsclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/secrets"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	sdktransport "github.com/jeremyhahn/go-quicbaas/sdk/go/transport"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	restkms "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/kms"
)

const (
	// kmsScopeResource is the scope resource of every /api/v1/kms route
	// outside /api/v1/kms/secrets: kms:read, kms:write or kms:delete.
	kmsScopeResource = "kms"
	// secretsScopeResource is the scope resource of the /api/v1/kms/secrets
	// routes: secrets:read, secrets:write or secrets:delete.
	secretsScopeResource = "secrets"
	// kmsSecretsRoutePrefix is the route template prefix of the secrets
	// routes the KMS router serves.
	kmsSecretsRoutePrefix = iamRESTParentPath + "/kms/secrets"
)

// kmsReadOnlyPosts are the KMS POST routes that only evaluate a request
// body, so they need kms:read, as gRPC Decrypt, Verify, VerifyHMAC, Hash and
// GenerateRandom do.
var kmsReadOnlyPosts = []string{
	"/kms/decrypt/{name}",
	"/kms/verify/{name}",
	"/kms/hmac/{name}/verify",
	"/kms/hash",
	"/kms/random",
	"/kms/decrypt",
	"/kms/batch-decrypt",
	"/kms/verify",
}

// SetKMSRouterHandlers mounts the name-keyed KMS router (keys, crypto, DEKs
// and secrets) at /api/v1/kms on the daemon REST listener over the SDK
// clients. Every route authenticates through guard and needs the kms:* or
// secrets:* scope its method names. Register it before SetKMSHandlers: the
// first matching route wins, so the guarded router serves every path both
// mount. A nil client is allowed; the router answers 503 for its routes.
func (s *RESTServer) SetKMSRouterHandlers(logger *logging.Logger, kms kmsclient.Client, crypto cryptoclient.Client, dek dekclient.Client, secrets secretsclient.Client, guard *restapi.ScopeGuard) error {
	switch {
	case logger == nil:
		return ErrKMSRESTUnavailable{Reason: "no logger"}
	case guard == nil:
		return ErrKMSRESTUnavailable{Reason: "no REST scope guard"}
	}
	respWriter := response.NewResponseWriter(logger, nil)
	authz := kmsRESTAuthorization{guard: guard, respWriter: respWriter}
	parent := s.router.PathPrefix(iamRESTParentPath).Subrouter()
	parent.Use(authz.authorize)
	// The KMS router's /kms base path is relative to the /api/v1 parent.
	restkms.NewKMSRouter(logger, kms, crypto, dek, secrets, respWriter).RegisterRoutes(parent)
	s.logger.Info("KMS REST routes registered")
	return nil
}

// kmsRESTAuthorization authenticates a KMS REST request through the daemon
// REST scope guard and requires the scope its route and method name.
type kmsRESTAuthorization struct {
	guard      *restapi.ScopeGuard
	respWriter response.HttpWriter
}

// authorize answers 401 for a missing or invalid credential and 403 for a
// caller without the route's scope.
func (a kmsRESTAuthorization) authorize(next http.Handler) http.Handler {
	return a.guard.Authenticate(func(w http.ResponseWriter, r *http.Request, caller *platformtoken.AuthorizedContext) {
		scope, err := kmsRouteScope(r.Method, restRouteTemplate(r))
		if err != nil {
			a.respWriter.Error403(w, r, err, nil)
			return
		}
		if err := caller.RequireScope(scope); err != nil {
			a.respWriter.Error403(w, r, restapi.ErrRouteForbidden{Scope: scope, Reason: err.Error()}, nil)
			return
		}
		if caller.TenantID == "" {
			a.respWriter.Error403(w, r, ErrKMSRESTNoTenant{Subject: caller.Subject}, nil)
			return
		}
		// The KMS, crypto, DEK and secrets SDK calls take their tenant from
		// the request context; without one they would run in system scope.
		next.ServeHTTP(w, r.WithContext(sdktransport.ContextWithTenant(r.Context(), caller.TenantID)))
	})
}

// kmsRouteScope is the scope a KMS router request needs: secrets:<action>
// under /api/v1/kms/secrets, kms:<action> everywhere else.
func kmsRouteScope(method, route string) (string, error) {
	resource, readOnlyPosts := kmsScopeResource, kmsReadOnlyPosts
	if strings.HasPrefix(route, kmsSecretsRoutePrefix) {
		resource, readOnlyPosts = secretsScopeResource, nil
	}
	action, err := restScopeAction(resource, readOnlyPosts, method, route)
	if err != nil {
		return "", err
	}
	return resource + ":" + action, nil
}
