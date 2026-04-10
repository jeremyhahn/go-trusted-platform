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

package kms

import (
	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-quicbaas/api/proto"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

const (
	basePath = "/api/v1/kms"
)

// KMSRouter provides REST routing for KMS operations
type KMSRouter struct {
	handlers *KMSHandlers
}

// NewKMSRouter creates a new KMSRouter instance
func NewKMSRouter(
	logger *logging.Logger,
	keyMgmtClient proto.KeyManagementClient,
	cryptoClient proto.CryptoClient,
	dekMgmtClient proto.DEKManagementClient,
	secretsClient proto.SecretsManagementClient,
	respWriter response.HttpWriter,
) *KMSRouter {
	return &KMSRouter{
		handlers: NewKMSHandlers(logger, keyMgmtClient, cryptoClient, dekMgmtClient, secretsClient, respWriter),
	}
}

// RegisterRoutes registers all KMS REST routes on the provided router
func (r *KMSRouter) RegisterRoutes(router *mux.Router) {
	// Create subrouter for KMS endpoints
	kmsRouter := router.PathPrefix(basePath).Subrouter()

	// Register all route groups
	r.registerKeyManagementRoutes(kmsRouter)
	r.registerCryptoRoutes(kmsRouter)
	r.registerDEKManagementRoutes(kmsRouter)
	r.registerSecretsRoutes(kmsRouter)
	r.registerBackendRoutes(kmsRouter)
}

// registerKeyManagementRoutes registers key management endpoints
// POST   /api/v1/kms/keys                    - Generate key
// POST   /api/v1/kms/keys/import             - Import key
// GET    /api/v1/kms/keys                    - List keys
// GET    /api/v1/kms/keys/{name}             - Get key
// POST   /api/v1/kms/keys/{name}/rotate      - Rotate key
// DELETE /api/v1/kms/keys/{name}             - Delete key
// PUT    /api/v1/kms/keys/{name}/status      - Update key status
// GET    /api/v1/kms/keys/{name}/versions    - List key versions
func (r *KMSRouter) registerKeyManagementRoutes(router *mux.Router) {
	// Key special action routes (must be before {name} routes to avoid conflicts)
	router.HandleFunc("/keys/import", r.handlers.ImportKey).Methods("POST")

	// Key collection routes
	router.HandleFunc("/keys", r.handlers.GenerateKey).Methods("POST")
	router.HandleFunc("/keys", r.handlers.ListKeys).Methods("GET")

	// Key instance routes
	router.HandleFunc("/keys/{name}", r.handlers.GetKey).Methods("GET")
	router.HandleFunc("/keys/{name}", r.handlers.DeleteKey).Methods("DELETE")

	// Key action routes
	router.HandleFunc("/keys/{name}/rotate", r.handlers.RotateKey).Methods("POST")
	router.HandleFunc("/keys/{name}/status", r.handlers.UpdateKeyStatus).Methods("PUT")
	router.HandleFunc("/keys/{name}/versions", r.handlers.ListKeyVersions).Methods("GET")
}

// registerCryptoRoutes registers crypto operation endpoints
// POST   /api/v1/kms/encrypt/{name}          - Encrypt data
// POST   /api/v1/kms/decrypt/{name}          - Decrypt data
// POST   /api/v1/kms/sign/{name}             - Sign data
// POST   /api/v1/kms/verify/{name}           - Verify signature
// POST   /api/v1/kms/hmac/{name}             - Generate HMAC
// POST   /api/v1/kms/hmac/{name}/verify      - Verify HMAC
// POST   /api/v1/kms/hash                    - Compute hash
// POST   /api/v1/kms/random                  - Generate random bytes
func (r *KMSRouter) registerCryptoRoutes(router *mux.Router) {
	// Encryption/Decryption routes
	router.HandleFunc("/encrypt/{name}", r.handlers.Encrypt).Methods("POST")
	router.HandleFunc("/decrypt/{name}", r.handlers.Decrypt).Methods("POST")

	// Signing/Verification routes
	router.HandleFunc("/sign/{name}", r.handlers.Sign).Methods("POST")
	router.HandleFunc("/verify/{name}", r.handlers.Verify).Methods("POST")

	// HMAC routes (verify must be before the general hmac route to avoid conflicts)
	router.HandleFunc("/hmac/{name}/verify", r.handlers.VerifyHMAC).Methods("POST")
	router.HandleFunc("/hmac/{name}", r.handlers.HMAC).Methods("POST")

	// Hash route (no key required)
	router.HandleFunc("/hash", r.handlers.Hash).Methods("POST")

	// Random bytes generation route
	router.HandleFunc("/random", r.handlers.GenerateRandom).Methods("POST")
}

// registerDEKManagementRoutes registers DEK management endpoints
// POST   /api/v1/kms/deks                    - Create DEK
// GET    /api/v1/kms/deks                    - List DEKs
// GET    /api/v1/kms/deks/{path:.*}          - Get DEK (path can contain slashes)
// POST   /api/v1/kms/deks/{path:.*}/rotate   - Rotate DEK
// DELETE /api/v1/kms/deks/{path:.*}          - Delete DEK
// GET    /api/v1/kms/deks/{path:.*}/status   - Get DEK status
func (r *KMSRouter) registerDEKManagementRoutes(router *mux.Router) {
	// DEK collection routes
	router.HandleFunc("/deks", r.handlers.CreateDEK).Methods("POST")
	router.HandleFunc("/deks", r.handlers.ListDEKs).Methods("GET")

	// DEK status route (must be before general path routes)
	router.HandleFunc("/deks/{path:.+}/status", r.handlers.GetDEKStatus).Methods("GET")
	router.HandleFunc("/deks/{path:.+}/rotate", r.handlers.RotateDEK).Methods("POST")

	// DEK instance routes (path can contain slashes)
	router.HandleFunc("/deks/{path:.+}", r.handlers.GetDEK).Methods("GET")
	router.HandleFunc("/deks/{path:.+}", r.handlers.DeleteDEK).Methods("DELETE")
}

// registerSecretsRoutes registers secrets management endpoints
// POST   /api/v1/kms/secrets                             - Store secret
// GET    /api/v1/kms/secrets                             - List secrets
// GET    /api/v1/kms/secrets?prefix=...                  - Get secrets by prefix
// GET    /api/v1/kms/secrets/{name}                      - Get secret
// DELETE /api/v1/kms/secrets/{name}                      - Delete secret
// POST   /api/v1/kms/secrets/{name}/rotate               - Rotate secret
// GET    /api/v1/kms/secrets/{name}/versions             - List secret versions
// GET    /api/v1/kms/secrets/{name}/versions/{version}   - Get secret version
// POST   /api/v1/kms/secrets/{name}/rollback             - Rollback secret
// PUT    /api/v1/kms/secrets/{name}/status               - Update secret status
// PUT    /api/v1/kms/secrets/{name}/policy               - Set rotation policy
// GET    /api/v1/kms/secrets/{name}/policy               - Get rotation policy
func (r *KMSRouter) registerSecretsRoutes(router *mux.Router) {
	// Secrets collection routes
	router.HandleFunc("/secrets", r.handlers.StoreSecret).Methods("POST")
	router.HandleFunc("/secrets", r.handlers.ListSecrets).Methods("GET")

	// Secret version routes (must be before {name} routes to avoid conflicts)
	router.HandleFunc("/secrets/{name}/versions/{version}", r.handlers.GetSecretVersion).Methods("GET")
	router.HandleFunc("/secrets/{name}/versions", r.handlers.ListSecretVersions).Methods("GET")

	// Secret action routes
	router.HandleFunc("/secrets/{name}/rotate", r.handlers.RotateSecret).Methods("POST")
	router.HandleFunc("/secrets/{name}/rollback", r.handlers.RollbackSecret).Methods("POST")
	router.HandleFunc("/secrets/{name}/status", r.handlers.UpdateSecretStatus).Methods("PUT")
	router.HandleFunc("/secrets/{name}/policy", r.handlers.SetRotationPolicy).Methods("PUT")
	router.HandleFunc("/secrets/{name}/policy", r.handlers.GetRotationPolicy).Methods("GET")

	// Secret instance routes
	router.HandleFunc("/secrets/{name}", r.handlers.GetSecret).Methods("GET")
	router.HandleFunc("/secrets/{name}", r.handlers.DeleteSecret).Methods("DELETE")
}

// registerBackendRoutes registers backend operation endpoints
// GET    /api/v1/kms/backend/status          - Backend status
// POST   /api/v1/kms/backend/test            - Backend test
func (r *KMSRouter) registerBackendRoutes(router *mux.Router) {
	router.HandleFunc("/backend/status", r.handlers.BackendStatus).Methods("GET")
	router.HandleFunc("/backend/test", r.handlers.BackendTest).Methods("POST")
}
