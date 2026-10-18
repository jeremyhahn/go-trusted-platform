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

// Package kms implements REST endpoints under /api/v1/kms.
//
// Per project convention every backend service is consumed exclusively
// through the go-quicbaas SDK; the REST handlers never reach into the
// proto/gRPC layer directly. This router takes the four QuicBaaS SDK
// clients (kms, crypto, dek, secrets) wired by the daemon and surfaces
// them under the WebUI's REST URL contract.
package kms

import (
	"net/http"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/router"

	cryptoclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/crypto"
	dekclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/dek"
	kmsclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"
	secretsclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/secrets"
)

const basePath = "/kms"

// BasePath is the path every KMS route is mounted under, relative to the
// /api/v1 router.
const BasePath = basePath

// The go-quicbaas gRPC services the handlers' SDK clients call. A route's
// RPC names the method whose scope guards the route on the daemon REST
// listener (pkg/api/grpc/method_permissions.go).
const (
	keyManagementRPC = "/quicbaas.kms.v1.KeyManagement/"
	cryptoRPC        = "/quicbaas.kms.v1.Crypto/"
	dekRPC           = "/quicbaas.kms.v1.DEKManagement/"
	secretsRPC       = "/quicbaas.kms.v1.SecretsManagement/"
)

// Route is one KMS REST endpoint: its method and path under BasePath, the
// gRPC method it answers for, and the handler that serves it.
type Route struct {
	Method  string
	Path    string
	RPC     string
	Handler http.HandlerFunc
}

// KMSRouter wires REST endpoints onto the QuicBaaS SDK clients.
type KMSRouter struct {
	handlers *Handlers
	router.WebServiceRouter
}

// NewKMSRouter constructs a router from the four SDK clients. Any of
// them may be nil; the corresponding handlers will return a service
// unavailable envelope on call.
func NewKMSRouter(
	logger *logging.Logger,
	kms kmsclient.Client,
	crypto cryptoclient.Client,
	dek dekclient.Client,
	secrets secretsclient.Client,
	respWriter response.HttpWriter,
) *KMSRouter {
	return &KMSRouter{
		handlers: NewHandlers(logger, kms, crypto, dek, secrets, respWriter),
	}
}

// RegisterRoutes mounts every KMS endpoint under /api/v1/kms.
//
//	# Key management
//	GET    /api/v1/kms/keys                     - ListKeys
//	POST   /api/v1/kms/keys                     - GenerateKey
//	POST   /api/v1/kms/keys/import              - ImportKey
//	GET    /api/v1/kms/keys/{name}              - GetKey
//	DELETE /api/v1/kms/keys/{name}              - DeleteKey
//	POST   /api/v1/kms/keys/{name}/rotate       - RotateKey
//	POST   /api/v1/kms/keys/{name}/revoke       - RevokeKey
//	PUT    /api/v1/kms/keys/{name}/status       - UpdateKeyStatus
//	GET    /api/v1/kms/keys/{name}/versions     - ListKeyVersions
//	GET    /api/v1/kms/keys/{name}/metadata     - GetKeyMetadata
//	PUT    /api/v1/kms/keys/{name}/metadata     - UpdateKeyMetadata
//	GET    /api/v1/kms/keys/{name}/policy       - GetKeyPolicy
//	PUT    /api/v1/kms/keys/{name}/policy       - SetKeyPolicy
//	GET    /api/v1/kms/algorithms               - ListAlgorithms
//	GET    /api/v1/kms/backend/status           - BackendStatus
//
//	# Crypto operations
//	POST   /api/v1/kms/encrypt/{name}           - Encrypt
//	POST   /api/v1/kms/decrypt/{name}           - Decrypt
//	POST   /api/v1/kms/sign/{name}              - Sign
//	POST   /api/v1/kms/verify/{name}            - Verify
//	POST   /api/v1/kms/hmac/{name}              - HMAC
//	POST   /api/v1/kms/hmac/{name}/verify       - VerifyHMAC
//	POST   /api/v1/kms/hash                     - Hash
//	POST   /api/v1/kms/random                   - GenerateRandom
//
//	# DEKs
//	GET    /api/v1/kms/deks                     - ListDEKs
//	POST   /api/v1/kms/deks                     - CreateDEK
//	GET    /api/v1/kms/deks/{path:.+}/status    - GetDEKStatus
//	POST   /api/v1/kms/deks/{path:.+}/rotate    - RotateDEK
//	GET    /api/v1/kms/deks/{path:.+}           - GetDEK
//	DELETE /api/v1/kms/deks/{path:.+}           - DeleteDEK
//
//	# Secrets
//	GET    /api/v1/kms/secrets                       - ListSecrets
//	POST   /api/v1/kms/secrets                       - StoreSecret
//	GET    /api/v1/kms/secrets/{name}                - GetSecret
//	DELETE /api/v1/kms/secrets/{name}                - DeleteSecret
//	POST   /api/v1/kms/secrets/{name}/rotate         - RotateSecret
//	POST   /api/v1/kms/secrets/{name}/rollback       - RollbackSecret
//	PUT    /api/v1/kms/secrets/{name}/status         - UpdateSecretStatus
//	GET    /api/v1/kms/secrets/{name}/versions       - ListSecretVersions
//	GET    /api/v1/kms/secrets/{name}/versions/{ver} - GetSecretVersion
//	GET    /api/v1/kms/secrets/{name}/policy         - GetRotationPolicy
//	PUT    /api/v1/kms/secrets/{name}/policy         - SetRotationPolicy
func (r *KMSRouter) RegisterRoutes(parent *mux.Router) {
	sr := parent.PathPrefix(basePath).Subrouter()
	// Secret paths and DEK paths contain slashes ("db/password"), which a
	// client sends escaped as %2F. Matching on the encoded path keeps such a
	// name inside its single {name} or {path} segment; the handlers unescape
	// the variable (Handlers.pathVar).
	sr.UseEncodedPath()
	for _, route := range r.Routes() {
		sr.HandleFunc(route.Path, route.Handler).Methods(route.Method)
	}
}

// Routes returns the KMS REST routes of docs/kms/api.md, in registration
// order: a literal segment is registered before the {name} or {path:.+}
// pattern it would otherwise be swallowed by.
//
// Data keys are minted and returned, never stored; stored DEKs are /deks.
func (r *KMSRouter) Routes() []Route {
	h := r.handlers
	return []Route{
		// Keys
		{http.MethodPost, "/keys/import", keyManagementRPC + "ImportKey", h.ImportKey},
		{http.MethodPost, "/keys", keyManagementRPC + "GenerateKey", h.GenerateKey},
		{http.MethodGet, "/keys", keyManagementRPC + "ListKeys", h.ListKeys},
		{http.MethodGet, "/keys/{name}", keyManagementRPC + "GetKey", h.GetKey},
		{http.MethodDelete, "/keys/{name}", keyManagementRPC + "DeleteKey", h.DeleteKey},
		{http.MethodPost, "/keys/{name}/rotate", keyManagementRPC + "RotateKey", h.RotateKey},
		{http.MethodPost, "/keys/{name}/revoke", keyManagementRPC + "RevokeKey", h.RevokeKey},
		{http.MethodPut, "/keys/{name}/status", keyManagementRPC + "UpdateKeyStatus", h.UpdateKeyStatus},
		{http.MethodGet, "/keys/{name}/versions", keyManagementRPC + "ListKeyVersions", h.ListKeyVersions},
		{http.MethodGet, "/keys/{name}/metadata", keyManagementRPC + "GetKeyMetadata", h.GetKeyMetadata},
		{http.MethodPut, "/keys/{name}/metadata", keyManagementRPC + "UpdateKeyMetadata", h.UpdateKeyMetadata},
		{http.MethodGet, "/keys/{name}/policy", keyManagementRPC + "GetKeyPolicy", h.GetKeyPolicy},
		{http.MethodPut, "/keys/{name}/policy", keyManagementRPC + "SetKeyPolicy", h.SetKeyPolicy},
		{http.MethodGet, "/algorithms", keyManagementRPC + "GetSupportedAlgorithms", h.ListAlgorithms},
		{http.MethodGet, "/backend/status", keyManagementRPC + "BackendStatus", h.BackendStatus},

		// Crypto
		{http.MethodPost, "/encrypt/{name}", cryptoRPC + "Encrypt", h.Encrypt},
		{http.MethodPost, "/decrypt/{name}", cryptoRPC + "Decrypt", h.Decrypt},
		{http.MethodPost, "/sign/{name}", cryptoRPC + "Sign", h.Sign},
		{http.MethodPost, "/verify/{name}", cryptoRPC + "Verify", h.Verify},
		{http.MethodPost, "/hmac/{name}/verify", cryptoRPC + "VerifyHMAC", h.VerifyHMAC},
		{http.MethodPost, "/hmac/{name}", cryptoRPC + "GenerateHMAC", h.HMAC},
		{http.MethodPost, "/hash", cryptoRPC + "Hash", h.Hash},
		{http.MethodPost, "/random", cryptoRPC + "GenerateRandom", h.GenerateRandom},
		{http.MethodPost, "/data-keys", cryptoRPC + "GenerateDataKey", h.GenerateDataKey},
		{http.MethodPost, "/data-keys/wrapped", cryptoRPC + "GenerateWrappedDataKey", h.GenerateWrappedDataKey},

		// DEKs
		{http.MethodPost, "/deks", dekRPC + "CreateDEK", h.CreateDEK},
		{http.MethodGet, "/deks", dekRPC + "ListDEKs", h.ListDEKs},
		{http.MethodGet, "/deks/{path:.+}/status", dekRPC + "GetDEKStatus", h.GetDEKStatus},
		{http.MethodPost, "/deks/{path:.+}/rotate", dekRPC + "RotateDEK", h.RotateDEK},
		{http.MethodGet, "/deks/{path:.+}", dekRPC + "GetDEK", h.GetDEK},
		{http.MethodDelete, "/deks/{path:.+}", dekRPC + "DeleteDEK", h.DeleteDEK},

		// Secrets
		{http.MethodPost, "/secrets", secretsRPC + "StoreSecret", h.StoreSecret},
		{http.MethodGet, "/secrets", secretsRPC + "ListSecrets", h.ListSecrets},
		{http.MethodGet, "/secrets/{name}/versions/{version}", secretsRPC + "GetSecretVersion", h.GetSecretVersion},
		{http.MethodGet, "/secrets/{name}/versions", secretsRPC + "ListSecretVersions", h.ListSecretVersions},
		{http.MethodPost, "/secrets/{name}/rotate", secretsRPC + "RotateSecret", h.RotateSecret},
		{http.MethodPost, "/secrets/{name}/rollback", secretsRPC + "RollbackSecret", h.RollbackSecret},
		{http.MethodPut, "/secrets/{name}/status", secretsRPC + "UpdateSecretStatus", h.UpdateSecretStatus},
		{http.MethodPut, "/secrets/{name}/policy", secretsRPC + "SetRotationPolicy", h.SetRotationPolicy},
		{http.MethodGet, "/secrets/{name}/policy", secretsRPC + "GetRotationPolicy", h.GetRotationPolicy},
		{http.MethodGet, "/secrets/{name}", secretsRPC + "GetSecret", h.GetSecret},
		{http.MethodDelete, "/secrets/{name}", secretsRPC + "DeleteSecret", h.DeleteSecret},
	}
}
