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

package eab

import (
	"net/http"
	"strconv"

	"github.com/gorilla/mux"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/internal/protorest"
)

// Handlers serves /api/v1/eab.
type Handlers struct {
	logger     *logging.Logger
	server     platformv1.EABServiceServer
	respWriter response.HttpWriter
}

// NewHandlers wires the supplied server.
func NewHandlers(
	logger *logging.Logger,
	server platformv1.EABServiceServer,
	respWriter response.HttpWriter,
) *Handlers {
	return &Handlers{logger: logger, server: server, respWriter: respWriter}
}

func (h *Handlers) ensure(w http.ResponseWriter, r *http.Request) bool {
	if h.server == nil {
		protorest.WriteError(w, r, h.respWriter, &protorest.ErrServiceUnavailable{Service: "eab"})
		return false
	}
	return true
}

func (h *Handlers) parseID(w http.ResponseWriter, r *http.Request) (uint64, bool) {
	raw := mux.Vars(r)["id"]
	v, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		h.respWriter.Error400(w, r, &protorest.ErrInvalidQuery{Name: "id", Value: raw, Cause: err})
		return 0, false
	}
	return v, true
}

// ListCredentials handles GET /api/v1/eab/credentials.
func (h *Handlers) ListCredentials(w http.ResponseWriter, r *http.Request) {
	if !h.ensure(w, r) {
		return
	}
	resp, err := h.server.ListCredentials(r.Context(), &platformv1.ListEABCredentialsRequest{})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// CreateCredential handles POST /api/v1/eab/credentials.
func (h *Handlers) CreateCredential(w http.ResponseWriter, r *http.Request) {
	if !h.ensure(w, r) {
		return
	}
	req := &platformv1.CreateEABCredentialRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	resp, err := h.server.CreateCredential(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccessStatus(w, r, h.respWriter, http.StatusCreated, resp)
}

// GetCredential handles GET /api/v1/eab/credentials/{id}.
func (h *Handlers) GetCredential(w http.ResponseWriter, r *http.Request) {
	if !h.ensure(w, r) {
		return
	}
	id, ok := h.parseID(w, r)
	if !ok {
		return
	}
	resp, err := h.server.GetCredential(r.Context(), &platformv1.GetEABCredentialRequest{CredentialId: id})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// DeleteCredential handles DELETE /api/v1/eab/credentials/{id}.
func (h *Handlers) DeleteCredential(w http.ResponseWriter, r *http.Request) {
	if !h.ensure(w, r) {
		return
	}
	id, ok := h.parseID(w, r)
	if !ok {
		return
	}
	resp, err := h.server.DeleteCredential(r.Context(), &platformv1.DeleteEABCredentialRequest{CredentialId: id})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// RevokeCredential handles POST /api/v1/eab/credentials/{id}/revoke.
func (h *Handlers) RevokeCredential(w http.ResponseWriter, r *http.Request) {
	if !h.ensure(w, r) {
		return
	}
	id, ok := h.parseID(w, r)
	if !ok {
		return
	}
	req := &platformv1.RevokeEABCredentialRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	req.CredentialId = id
	resp, err := h.server.RevokeCredential(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// MarkCredentialUsed handles POST /api/v1/eab/credentials/{id}/used.
func (h *Handlers) MarkCredentialUsed(w http.ResponseWriter, r *http.Request) {
	if !h.ensure(w, r) {
		return
	}
	id, ok := h.parseID(w, r)
	if !ok {
		return
	}
	resp, err := h.server.MarkCredentialUsed(r.Context(), &platformv1.MarkEABCredentialUsedRequest{CredentialId: id})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// GetCredentialQRCode handles GET /api/v1/eab/credentials/{id}/qrcode.
func (h *Handlers) GetCredentialQRCode(w http.ResponseWriter, r *http.Request) {
	if !h.ensure(w, r) {
		return
	}
	id, ok := h.parseID(w, r)
	if !ok {
		return
	}
	size, err := protorest.QueryUint32(r, "size")
	if err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	resp, err := h.server.GetCredentialQRCode(r.Context(), &platformv1.GetEABCredentialQRCodeRequest{
		CredentialId: id,
		Size:         int32(size),
	})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// GetEnrollmentURL handles GET /api/v1/eab/credentials/{id}/url.
func (h *Handlers) GetEnrollmentURL(w http.ResponseWriter, r *http.Request) {
	if !h.ensure(w, r) {
		return
	}
	id, ok := h.parseID(w, r)
	if !ok {
		return
	}
	resp, err := h.server.GetEnrollmentURL(r.Context(), &platformv1.GetEABEnrollmentURLRequest{
		CredentialId: id,
		Path:         r.URL.Query().Get("path"),
	})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// GetCredentialByKeyID handles GET /api/v1/eab/credentials/key/{key}.
func (h *Handlers) GetCredentialByKeyID(w http.ResponseWriter, r *http.Request) {
	if !h.ensure(w, r) {
		return
	}
	resp, err := h.server.GetCredentialByKeyID(r.Context(), &platformv1.GetEABCredentialByKeyIDRequest{KeyId: mux.Vars(r)["key"]})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// ValidateCredential handles POST /api/v1/eab/credentials/validate.
func (h *Handlers) ValidateCredential(w http.ResponseWriter, r *http.Request) {
	if !h.ensure(w, r) {
		return
	}
	req := &platformv1.ValidateEABCredentialRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	resp, err := h.server.ValidateCredential(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// CleanupExpired handles POST /api/v1/eab/credentials/cleanup.
func (h *Handlers) CleanupExpired(w http.ResponseWriter, r *http.Request) {
	if !h.ensure(w, r) {
		return
	}
	resp, err := h.server.CleanupExpiredCredentials(r.Context(), &platformv1.CleanupExpiredEABCredentialsRequest{})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}
