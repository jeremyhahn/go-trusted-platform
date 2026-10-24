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
	"math"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/internal/protorest"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// ErrUnknownStatusFilter indicates the status query parameter is not
// one of the known credential statuses.
type ErrUnknownStatusFilter struct {
	Value string
}

// Error implements the error interface.
func (e *ErrUnknownStatusFilter) Error() string {
	return "eab: unknown status filter: " + e.Value
}

// ErrQRCodeSizeOutOfRange reports a `size` query parameter larger than the
// int32 wire field can carry.
type ErrQRCodeSizeOutOfRange struct {
	Value string
}

func (e *ErrQRCodeSizeOutOfRange) Error() string {
	return "eab: qrcode size out of range: " + e.Value
}

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
//
// Filters are supplied as query parameters so the GET request carries no
// body: tenant_id, profile_id, active_only, status (active | revoked |
// expired | used), page and page_size.
func (h *Handlers) ListCredentials(w http.ResponseWriter, r *http.Request) {
	if !h.ensure(w, r) {
		return
	}
	req, err := listCredentialsRequestFromQuery(r)
	if err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	resp, err := h.server.ListCredentials(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// eabStatusFilterFromQuery maps the status query parameter onto the
// platform.v1 enum with O(1) lookup. Both the short domain names and the
// full proto enum value names are accepted (the SDK REST adapter's
// generic enum encoding emits the latter).
var eabStatusFilterFromQuery = map[string]platformv1.EABCredentialStatus{
	"active":  platformv1.EABCredentialStatus_EAB_CREDENTIAL_STATUS_ACTIVE,
	"revoked": platformv1.EABCredentialStatus_EAB_CREDENTIAL_STATUS_REVOKED,
	"expired": platformv1.EABCredentialStatus_EAB_CREDENTIAL_STATUS_EXPIRED,
	"used":    platformv1.EABCredentialStatus_EAB_CREDENTIAL_STATUS_USED,

	"EAB_CREDENTIAL_STATUS_ACTIVE":  platformv1.EABCredentialStatus_EAB_CREDENTIAL_STATUS_ACTIVE,
	"EAB_CREDENTIAL_STATUS_REVOKED": platformv1.EABCredentialStatus_EAB_CREDENTIAL_STATUS_REVOKED,
	"EAB_CREDENTIAL_STATUS_EXPIRED": platformv1.EABCredentialStatus_EAB_CREDENTIAL_STATUS_EXPIRED,
	"EAB_CREDENTIAL_STATUS_USED":    platformv1.EABCredentialStatus_EAB_CREDENTIAL_STATUS_USED,
}

// listCredentialsRequestFromQuery builds a ListEABCredentialsRequest
// from the request query parameters.
func listCredentialsRequestFromQuery(r *http.Request) (*platformv1.ListEABCredentialsRequest, error) {
	profileID, err := protorest.QueryUint64(r, "profile_id")
	if err != nil {
		return nil, err
	}
	activeOnly, err := protorest.QueryBool(r, "active_only")
	if err != nil {
		return nil, err
	}
	page, err := protorest.QueryUint32(r, "page")
	if err != nil {
		return nil, err
	}
	pageSize, err := protorest.QueryUint32(r, "page_size")
	if err != nil {
		return nil, err
	}

	req := &platformv1.ListEABCredentialsRequest{
		TenantId:   r.URL.Query().Get("tenant_id"),
		ProfileId:  profileID,
		ActiveOnly: activeOnly,
	}
	if statusRaw := r.URL.Query().Get("status"); statusRaw != "" {
		statusFilter, ok := eabStatusFilterFromQuery[statusRaw]
		if !ok {
			return nil, &protorest.ErrInvalidQuery{
				Name:  "status",
				Value: statusRaw,
				Cause: &ErrUnknownStatusFilter{Value: statusRaw},
			}
		}
		req.StatusFilter = statusFilter
	}
	if page > 0 || pageSize > 0 {
		req.Pagination = &platformv1.PaginationRequest{
			Page:     page,
			PageSize: pageSize,
		}
	}
	return req, nil
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
	size, err := qrCodeSizeFromQuery(r)
	if err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	resp, err := h.server.GetCredentialQRCode(r.Context(), &platformv1.GetEABCredentialQRCodeRequest{
		CredentialId: id,
		Size:         size,
	})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// qrCodeSizeFromQuery reads the optional `size` query parameter. The wire
// field is an int32, so a value above math.MaxInt32 is refused rather than
// wrapped into a negative size.
func qrCodeSizeFromQuery(r *http.Request) (int32, error) {
	size, err := protorest.QueryUint32(r, "size")
	if err != nil {
		return 0, err
	}
	if size > math.MaxInt32 {
		raw := r.URL.Query().Get("size")
		return 0, &protorest.ErrInvalidQuery{
			Name:  "size",
			Value: raw,
			Cause: &ErrQRCodeSizeOutOfRange{Value: raw},
		}
	}
	return int32(size), nil
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

// CleanupExpired handles POST /api/v1/eab/credentials/cleanup. The
// optional tenant filter is read from the JSON body ({"tenant_id":
// "..."}) with a query-parameter fallback for body-less clients.
func (h *Handlers) CleanupExpired(w http.ResponseWriter, r *http.Request) {
	if !h.ensure(w, r) {
		return
	}
	req := &platformv1.CleanupExpiredEABCredentialsRequest{}
	if r.Body != nil && r.ContentLength != 0 {
		if err := protorest.DecodeRequest(r, req); err != nil {
			h.respWriter.Error400(w, r, err)
			return
		}
	}
	if req.TenantId == "" {
		req.TenantId = r.URL.Query().Get("tenant_id")
	}
	resp, err := h.server.CleanupExpiredCredentials(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}
