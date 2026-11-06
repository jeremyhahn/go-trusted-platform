package daemon

import (
	"net/http"
	"strings"

	cryptoclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/crypto"
	dekclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/dek"
	kmsclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"
	secretsclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/secrets"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
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
	// kmsSecretVersionsRouteSuffix ends the route template that lists one
	// secret's versions.
	kmsSecretVersionsRouteSuffix = "/versions"
	// scopeActionList is the catalog action of the secret enumeration
	// routes: gRPC ListSecrets and ListSecretVersions require secrets:list.
	scopeActionList = "list"
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
func (s *RESTServer) SetKMSRouterHandlers(logger *logging.Logger, kms kmsclient.Client, crypto cryptoclient.Client, dek dekclient.Client, secrets secretsclient.Client, guard *restapi.ScopeGuard, systemTenantID string) error {
	switch {
	case logger == nil:
		return ErrKMSRESTUnavailable{Reason: "no logger"}
	case guard == nil:
		return ErrKMSRESTUnavailable{Reason: "no REST scope guard"}
	}
	respWriter := response.NewResponseWriter(logger, nil)
	authz := restScopeAuthorization{
		guard:      guard,
		respWriter: respWriter,
		routeScope: kmsRouteScope,
		callerGate: func(callerTenantID string) error {
			return kmsRouterTenantDecision(systemTenantID, callerTenantID)
		},
	}
	parent := s.router.PathPrefix(iamRESTParentPath).Subrouter()
	parent.Use(authz.authorize)
	// The KMS router's /kms base path is relative to the /api/v1 parent.
	restkms.NewKMSRouter(logger, kms, crypto, dek, secrets, respWriter).RegisterRoutes(parent)
	s.logger.Info("KMS REST routes registered")
	return nil
}

// ErrKMSRouterTenantUnbound refuses a tenant-bound caller on the KMS router.
// The embedded KMS and secrets services select their namespace from a tenant
// the SDK gives the platform no way to set, so a tenant caller would be
// served from the system namespace; the router fails closed instead.
type ErrKMSRouterTenantUnbound struct {
	Tenant string
}

func (e ErrKMSRouterTenantUnbound) Error() string {
	return "KMS router: tenant " + e.Tenant + " refused: the KMS router serves only the system tenant until the SDK can bind a caller's tenant to the embedded KMS and secrets services"
}

// kmsRouterTenantDecision admits a caller with no tenant or the system
// tenant, and refuses every other tenant.
func kmsRouterTenantDecision(systemTenantID, callerTenantID string) error {
	if callerTenantID == "" || tenant.IsSystemTenant(systemTenantID, callerTenantID) {
		return nil
	}
	return ErrKMSRouterTenantUnbound{Tenant: callerTenantID}
}

// kmsRouteScope is the scope a KMS router request needs: secrets:<action>
// under /api/v1/kms/secrets, kms:<action> everywhere else.
func kmsRouteScope(method, route string) (string, error) {
	resource, readOnlyPosts := kmsScopeResource, kmsReadOnlyPosts
	if strings.HasPrefix(route, kmsSecretsRoutePrefix) {
		if isSecretEnumerationRoute(method, route) {
			return secretsScopeResource + ":" + scopeActionList, nil
		}
		resource, readOnlyPosts = secretsScopeResource, nil
	}
	action, err := restScopeAction(resource, readOnlyPosts, method, route)
	if err != nil {
		return "", err
	}
	return resource + ":" + action, nil
}

// isSecretEnumerationRoute reports whether a secrets route lists rather than
// reads: a GET on the secrets collection or on one secret's versions.
func isSecretEnumerationRoute(method, route string) bool {
	if method != http.MethodGet {
		return false
	}
	return route == kmsSecretsRoutePrefix || strings.HasSuffix(route, kmsSecretVersionsRouteSuffix)
}
