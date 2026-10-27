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

package rest

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/gorilla/mux"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// =============================================================================
// TPM REST Handler Errors
// =============================================================================

// ErrTPMServiceNotAvailable is returned when the physical TPM service is not
// configured or unavailable.
type ErrTPMServiceNotAvailable struct{}

func (e ErrTPMServiceNotAvailable) Error() string {
	return "TPM service not available"
}

// =============================================================================
// TPM Routes
// =============================================================================

// The scopes a platform token needs for each TPM route, the same tiers the
// gRPC TPMService and the QUIC 0x99 category enforce (docs/tpm/api.md §9).
const (
	tpmScopeRead   = "tpm:read"
	tpmScopeWrite  = "tpm:write"
	tpmScopeDelete = "tpm:delete"
)

// TPMHandlers serves the physical TPM over REST. Every route decodes the
// protobuf JSON request the SDK sends, runs the matching TPMService RPC on
// the daemon's TPM service and answers with its protobuf JSON response, so a
// REST call is the one gRPC, QUIC, MCP and Unix serve. Every route requires
// its scope, checked by the daemon's ScopeGuard: a platform bearer token, else
// the verified operator client certificate.
type TPMHandlers struct {
	protoResponder
	tpm   platformv1.TPMServiceServer
	guard *ScopeGuard
}

// tpmRoute is one TPM REST route and the scope it requires.
type tpmRoute struct {
	method  string
	path    string
	scope   string
	handler http.HandlerFunc
}

// NewTPMHandlers creates a new TPMHandlers instance.
func NewTPMHandlers(logger *slog.Logger) *TPMHandlers {
	if logger == nil {
		logger = slog.Default()
	}
	return &TPMHandlers{
		protoResponder: protoResponder{logger: logger},
	}
}

// WithTPMService sets the TPM service every route delegates to. Without one,
// every route answers 503.
func (h *TPMHandlers) WithTPMService(tpm platformv1.TPMServiceServer) *TPMHandlers {
	h.tpm = tpm
	return h
}

// WithScopeGuard sets the guard that checks every route's scope. Without
// one, every route refuses every request with 403.
func (h *TPMHandlers) WithScopeGuard(guard *ScopeGuard) *TPMHandlers {
	h.guard = guard
	return h
}

// RegisterRoutes registers all physical TPM routes on the provided router,
// each behind the scope it requires.
func (h *TPMHandlers) RegisterRoutes(router *mux.Router) {
	for _, route := range h.routes() {
		router.HandleFunc(route.path, h.guard.Require(route.scope, route.handler)).Methods(route.method)
	}
	h.logger.Info("TPM REST routes registered")
}

// routes is the TPM route table: the paths and verbs the SDK's REST
// transports map TPMService onto, each running that RPC under the scope the
// gRPC method catalog gives it. The Go SDK carries a key handle or NVRAM
// index in the body; the JavaScript SDK puts it in the path ({handle},
// {index}), so both forms are mounted. The device-identity routes (IDevID and
// IAK info and delete) are the daemon's own, in pkg/api/daemon/rest_idevid.go.
func (h *TPMHandlers) routes() []tpmRoute {
	return []tpmRoute{
		// TPM info and management
		{http.MethodGet, "/api/v1/tpm/info", tpmScopeRead, tpmRPC(h, platformv1.TPMServiceServer.Info)},
		{http.MethodPost, "/api/v1/tpm/provision", tpmScopeWrite, tpmRPC(h, platformv1.TPMServiceServer.Provision)},
		{http.MethodPost, "/api/v1/tpm/clear", tpmScopeDelete, tpmRPC(h, platformv1.TPMServiceServer.Clear)},
		{http.MethodGet, "/api/v1/tpm/capabilities", tpmScopeRead, tpmRPC(h, platformv1.TPMServiceServer.GetCapabilities)},
		{http.MethodGet, "/api/v1/tpm/platform", tpmScopeRead, tpmRPC(h, platformv1.TPMServiceServer.GetPlatformAttributes)},

		// Endorsement key
		{http.MethodGet, "/api/v1/tpm/ek", tpmScopeRead, tpmRPC(h, platformv1.TPMServiceServer.GetEK)},
		{http.MethodPost, "/api/v1/tpm/ek", tpmScopeWrite, tpmRPC(h, platformv1.TPMServiceServer.CreateEK)},
		{http.MethodDelete, "/api/v1/tpm/ek", tpmScopeDelete, tpmRPC(h, platformv1.TPMServiceServer.DeleteEK)},
		{http.MethodDelete, "/api/v1/tpm/ek/{handle}", tpmScopeDelete, tpmRPC(h, platformv1.TPMServiceServer.DeleteEK)},
		{http.MethodGet, "/api/v1/tpm/ek/certificate", tpmScopeRead, tpmRPC(h, platformv1.TPMServiceServer.GetEKCertificate)},
		{http.MethodPost, "/api/v1/tpm/ek/certificate", tpmScopeWrite, tpmRPC(h, platformv1.TPMServiceServer.ImportEKCertificate)},

		// Storage root key
		{http.MethodGet, "/api/v1/tpm/srk", tpmScopeRead, tpmRPC(h, platformv1.TPMServiceServer.GetSRK)},
		{http.MethodPost, "/api/v1/tpm/srk", tpmScopeWrite, tpmRPC(h, platformv1.TPMServiceServer.CreateSRK)},
		{http.MethodDelete, "/api/v1/tpm/srk", tpmScopeDelete, tpmRPC(h, platformv1.TPMServiceServer.DeleteSRK)},
		{http.MethodDelete, "/api/v1/tpm/srk/{handle}", tpmScopeDelete, tpmRPC(h, platformv1.TPMServiceServer.DeleteSRK)},

		// Attestation key
		{http.MethodGet, "/api/v1/tpm/ak", tpmScopeRead, tpmRPC(h, platformv1.TPMServiceServer.GetAK)},
		{http.MethodPost, "/api/v1/tpm/ak", tpmScopeWrite, tpmRPC(h, platformv1.TPMServiceServer.CreateAK)},
		// DeleteAK refuses (the IAK is not evicted); the refusal is 409 (#665).
		{http.MethodDelete, "/api/v1/tpm/ak", tpmScopeDelete, tpmRPC(h, platformv1.TPMServiceServer.DeleteAK)},
		{http.MethodDelete, "/api/v1/tpm/ak/{handle}", tpmScopeDelete, tpmRPC(h, platformv1.TPMServiceServer.DeleteAK)},

		// Credential activation (TPM2_MakeCredential, TPM2_ActivateCredential)
		{http.MethodPost, "/api/v1/tpm/make-credential", tpmScopeRead, tpmRPC(h, platformv1.TPMServiceServer.MakeCredential)},
		{http.MethodPost, "/api/v1/tpm/activate-credential", tpmScopeWrite, tpmRPC(h, platformv1.TPMServiceServer.ActivateCredential)},

		// Quote and attestation
		{http.MethodPost, "/api/v1/tpm/quote", tpmScopeRead, tpmRPC(h, platformv1.TPMServiceServer.Quote)},
		{http.MethodPost, "/api/v1/tpm/quote/verify", tpmScopeRead, tpmRPC(h, platformv1.TPMServiceServer.VerifyQuote)},
		{http.MethodPost, "/api/v1/tpm/certify", tpmScopeRead, tpmRPC(h, platformv1.TPMServiceServer.Certify)},

		// PCRs and the event log. POST /pcrs is the JavaScript SDK's form.
		{http.MethodGet, "/api/v1/tpm/pcrs", tpmScopeRead, tpmRPC(h, platformv1.TPMServiceServer.GetPCRs)},
		{http.MethodPost, "/api/v1/tpm/pcrs", tpmScopeRead, tpmRPC(h, platformv1.TPMServiceServer.GetPCRs)},
		{http.MethodPost, "/api/v1/tpm/pcrs/extend", tpmScopeWrite, tpmRPC(h, platformv1.TPMServiceServer.ExtendPCR)},
		{http.MethodGet, "/api/v1/tpm/eventlog", tpmScopeRead, tpmRPC(h, platformv1.TPMServiceServer.GetEventLog)},

		// NVRAM
		{http.MethodPost, "/api/v1/tpm/nvram", tpmScopeWrite, tpmRPC(h, platformv1.TPMServiceServer.DefineNVRAM)},
		{http.MethodGet, "/api/v1/tpm/nvram", tpmScopeRead, tpmRPC(h, platformv1.TPMServiceServer.ReadNVRAM)},
		{http.MethodPut, "/api/v1/tpm/nvram", tpmScopeWrite, tpmRPC(h, platformv1.TPMServiceServer.WriteNVRAM)},
		{http.MethodDelete, "/api/v1/tpm/nvram", tpmScopeDelete, tpmRPC(h, platformv1.TPMServiceServer.UndefineNVRAM)},
		{http.MethodGet, "/api/v1/tpm/nvram/{index}", tpmScopeRead, tpmRPC(h, platformv1.TPMServiceServer.ReadNVRAM)},
		{http.MethodPut, "/api/v1/tpm/nvram/{index}", tpmScopeWrite, tpmRPC(h, platformv1.TPMServiceServer.WriteNVRAM)},
		{http.MethodDelete, "/api/v1/tpm/nvram/{index}", tpmScopeDelete, tpmRPC(h, platformv1.TPMServiceServer.UndefineNVRAM)},

		// Random, seal and unseal
		{http.MethodPost, "/api/v1/tpm/random", tpmScopeRead, tpmRPC(h, platformv1.TPMServiceServer.GetRandom)},
		{http.MethodPost, "/api/v1/tpm/seal", tpmScopeWrite, tpmRPC(h, platformv1.TPMServiceServer.Seal)},
		{http.MethodPost, "/api/v1/tpm/unseal", tpmScopeRead, tpmRPC(h, platformv1.TPMServiceServer.Unseal)},
	}
}

// =============================================================================
// TPMService RPC Handlers
// =============================================================================

// tpmRPC serves one TPMService RPC over protobuf JSON (protoRPC).
func tpmRPC[Req any, PReq interface {
	*Req
	proto.Message
}, Resp proto.Message](h *TPMHandlers, rpc func(platformv1.TPMServiceServer, context.Context, PReq) (Resp, error)) http.HandlerFunc {
	return protoRPC(h.protoResponder, h.tpmService, rpc)
}

// tpmService returns the TPM service every route delegates to, or
// ErrTPMServiceNotAvailable when none is configured.
func (h *TPMHandlers) tpmService() (platformv1.TPMServiceServer, error) {
	if h.tpm == nil {
		return nil, ErrTPMServiceNotAvailable{}
	}
	return h.tpm, nil
}
