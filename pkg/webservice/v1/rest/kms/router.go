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

	// Keys
	sr.HandleFunc("/keys/import", r.handlers.ImportKey).Methods("POST")
	sr.HandleFunc("/keys", r.handlers.GenerateKey).Methods("POST")
	sr.HandleFunc("/keys", r.handlers.ListKeys).Methods("GET")
	sr.HandleFunc("/keys/{name}", r.handlers.GetKey).Methods("GET")
	sr.HandleFunc("/keys/{name}", r.handlers.DeleteKey).Methods("DELETE")
	sr.HandleFunc("/keys/{name}/rotate", r.handlers.RotateKey).Methods("POST")
	sr.HandleFunc("/keys/{name}/revoke", r.handlers.RevokeKey).Methods("POST")
	sr.HandleFunc("/keys/{name}/status", r.handlers.UpdateKeyStatus).Methods("PUT")
	sr.HandleFunc("/keys/{name}/versions", r.handlers.ListKeyVersions).Methods("GET")
	sr.HandleFunc("/keys/{name}/metadata", r.handlers.GetKeyMetadata).Methods("GET")
	sr.HandleFunc("/keys/{name}/metadata", r.handlers.UpdateKeyMetadata).Methods("PUT")
	sr.HandleFunc("/keys/{name}/policy", r.handlers.GetKeyPolicy).Methods("GET")
	sr.HandleFunc("/keys/{name}/policy", r.handlers.SetKeyPolicy).Methods("PUT")
	sr.HandleFunc("/algorithms", r.handlers.ListAlgorithms).Methods("GET")
	sr.HandleFunc("/backend/status", r.handlers.BackendStatus).Methods("GET")

	// Crypto
	sr.HandleFunc("/encrypt/{name}", r.handlers.Encrypt).Methods("POST")
	sr.HandleFunc("/decrypt/{name}", r.handlers.Decrypt).Methods("POST")
	sr.HandleFunc("/sign/{name}", r.handlers.Sign).Methods("POST")
	sr.HandleFunc("/verify/{name}", r.handlers.Verify).Methods("POST")
	sr.HandleFunc("/hmac/{name}/verify", r.handlers.VerifyHMAC).Methods("POST")
	sr.HandleFunc("/hmac/{name}", r.handlers.HMAC).Methods("POST")
	sr.HandleFunc("/hash", r.handlers.Hash).Methods("POST")
	sr.HandleFunc("/random", r.handlers.GenerateRandom).Methods("POST")

	// DEKs
	sr.HandleFunc("/deks", r.handlers.CreateDEK).Methods("POST")
	sr.HandleFunc("/deks", r.handlers.ListDEKs).Methods("GET")
	sr.HandleFunc("/deks/{path:.+}/status", r.handlers.GetDEKStatus).Methods("GET")
	sr.HandleFunc("/deks/{path:.+}/rotate", r.handlers.RotateDEK).Methods("POST")
	sr.HandleFunc("/deks/{path:.+}", r.handlers.GetDEK).Methods("GET")
	sr.HandleFunc("/deks/{path:.+}", r.handlers.DeleteDEK).Methods("DELETE")

	// Secrets
	sr.HandleFunc("/secrets", r.handlers.StoreSecret).Methods("POST")
	sr.HandleFunc("/secrets", r.handlers.ListSecrets).Methods("GET")
	sr.HandleFunc("/secrets/{name}/versions/{version}", r.handlers.GetSecretVersion).Methods("GET")
	sr.HandleFunc("/secrets/{name}/versions", r.handlers.ListSecretVersions).Methods("GET")
	sr.HandleFunc("/secrets/{name}/rotate", r.handlers.RotateSecret).Methods("POST")
	sr.HandleFunc("/secrets/{name}/rollback", r.handlers.RollbackSecret).Methods("POST")
	sr.HandleFunc("/secrets/{name}/status", r.handlers.UpdateSecretStatus).Methods("PUT")
	sr.HandleFunc("/secrets/{name}/policy", r.handlers.SetRotationPolicy).Methods("PUT")
	sr.HandleFunc("/secrets/{name}/policy", r.handlers.GetRotationPolicy).Methods("GET")
	sr.HandleFunc("/secrets/{name}", r.handlers.GetSecret).Methods("GET")
	sr.HandleFunc("/secrets/{name}", r.handlers.DeleteSecret).Methods("DELETE")
}
