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

package tenant

import (
	"net/http"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/internal/protorest"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// Handlers serves /api/v1/tenants.
type Handlers struct {
	logger     *logging.Logger
	server     platformv1.TenantServiceServer
	respWriter response.HttpWriter
}

// NewHandlers wires the supplied server.
func NewHandlers(
	logger *logging.Logger,
	server platformv1.TenantServiceServer,
	respWriter response.HttpWriter,
) *Handlers {
	return &Handlers{logger: logger, server: server, respWriter: respWriter}
}

func (h *Handlers) ensure(w http.ResponseWriter, r *http.Request) bool {
	if h.server == nil {
		protorest.WriteError(w, r, h.respWriter, &protorest.ErrServiceUnavailable{Service: "tenant"})
		return false
	}
	return true
}

// ListTenants handles GET /api/v1/tenants.
func (h *Handlers) ListTenants(w http.ResponseWriter, r *http.Request) {
	if !h.ensure(w, r) {
		return
	}
	resp, err := h.server.ListTenants(r.Context(), &platformv1.ListTenantsRequest{})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// CreateTenant handles POST /api/v1/tenants.
func (h *Handlers) CreateTenant(w http.ResponseWriter, r *http.Request) {
	if !h.ensure(w, r) {
		return
	}
	req := &platformv1.CreateTenantRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	resp, err := h.server.CreateTenant(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccessStatus(w, r, h.respWriter, http.StatusCreated, resp)
}

// GetTenant handles GET /api/v1/tenants/{id}.
func (h *Handlers) GetTenant(w http.ResponseWriter, r *http.Request) {
	if !h.ensure(w, r) {
		return
	}
	resp, err := h.server.GetTenant(r.Context(), &platformv1.GetTenantRequest{TenantId: mux.Vars(r)["id"]})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// GetTenantByName handles GET /api/v1/tenants/by-name/{name}.
func (h *Handlers) GetTenantByName(w http.ResponseWriter, r *http.Request) {
	if !h.ensure(w, r) {
		return
	}
	resp, err := h.server.GetTenantByName(r.Context(), &platformv1.GetTenantByNameRequest{Name: mux.Vars(r)["name"]})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// UpdateTenant handles PUT /api/v1/tenants/{id}.
func (h *Handlers) UpdateTenant(w http.ResponseWriter, r *http.Request) {
	if !h.ensure(w, r) {
		return
	}
	req := &platformv1.UpdateTenantRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	req.TenantId = mux.Vars(r)["id"]
	resp, err := h.server.UpdateTenant(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// DeleteTenant handles DELETE /api/v1/tenants/{id}.
func (h *Handlers) DeleteTenant(w http.ResponseWriter, r *http.Request) {
	if !h.ensure(w, r) {
		return
	}
	resp, err := h.server.DeleteTenant(r.Context(), &platformv1.DeleteTenantRequest{TenantId: mux.Vars(r)["id"]})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// SuspendTenant handles POST /api/v1/tenants/{id}/suspend.
func (h *Handlers) SuspendTenant(w http.ResponseWriter, r *http.Request) {
	if !h.ensure(w, r) {
		return
	}
	req := &platformv1.SuspendTenantRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	req.TenantId = mux.Vars(r)["id"]
	resp, err := h.server.SuspendTenant(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// ResumeTenant handles POST /api/v1/tenants/{id}/resume.
func (h *Handlers) ResumeTenant(w http.ResponseWriter, r *http.Request) {
	if !h.ensure(w, r) {
		return
	}
	resp, err := h.server.ResumeTenant(r.Context(), &platformv1.ResumeTenantRequest{TenantId: mux.Vars(r)["id"]})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// GetQuotas handles GET /api/v1/tenants/{id}/quotas.
func (h *Handlers) GetQuotas(w http.ResponseWriter, r *http.Request) {
	if !h.ensure(w, r) {
		return
	}
	resp, err := h.server.GetQuotas(r.Context(), &platformv1.GetQuotasRequest{TenantId: mux.Vars(r)["id"]})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// UpdateQuotas handles PUT /api/v1/tenants/{id}/quotas.
func (h *Handlers) UpdateQuotas(w http.ResponseWriter, r *http.Request) {
	if !h.ensure(w, r) {
		return
	}
	req := &platformv1.UpdateQuotasRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	req.TenantId = mux.Vars(r)["id"]
	resp, err := h.server.UpdateQuotas(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// GetUsage handles GET /api/v1/tenants/{id}/usage.
func (h *Handlers) GetUsage(w http.ResponseWriter, r *http.Request) {
	if !h.ensure(w, r) {
		return
	}
	resp, err := h.server.GetUsage(r.Context(), &platformv1.GetUsageRequest{TenantId: mux.Vars(r)["id"]})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// CheckQuota handles POST /api/v1/tenants/{id}/quota-check.
func (h *Handlers) CheckQuota(w http.ResponseWriter, r *http.Request) {
	if !h.ensure(w, r) {
		return
	}
	req := &platformv1.CheckQuotaRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	req.TenantId = mux.Vars(r)["id"]
	resp, err := h.server.CheckQuota(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// Sync handles POST /api/v1/tenants/sync.
func (h *Handlers) Sync(w http.ResponseWriter, r *http.Request) {
	if !h.ensure(w, r) {
		return
	}
	req := &platformv1.SyncTenantsRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	resp, err := h.server.Sync(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// RotateTenantDEK handles POST /api/v1/tenants/{id}/dek/rotate.
func (h *Handlers) RotateTenantDEK(w http.ResponseWriter, r *http.Request) {
	if !h.ensure(w, r) {
		return
	}
	resp, err := h.server.RotateTenantDEK(r.Context(), &platformv1.RotateTenantDEKRequest{TenantId: mux.Vars(r)["id"]})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// GetTenantDEKStatus handles GET /api/v1/tenants/{id}/dek.
func (h *Handlers) GetTenantDEKStatus(w http.ResponseWriter, r *http.Request) {
	if !h.ensure(w, r) {
		return
	}
	resp, err := h.server.GetTenantDEKStatus(r.Context(), &platformv1.GetTenantDEKStatusRequest{TenantId: mux.Vars(r)["id"]})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// InitBarrier handles POST /api/v1/tenants/{id}/barrier/init.
func (h *Handlers) InitBarrier(w http.ResponseWriter, r *http.Request) {
	if !h.ensure(w, r) {
		return
	}
	req := &platformv1.InitTenantBarrierRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	req.TenantId = mux.Vars(r)["id"]
	resp, err := h.server.InitTenantBarrier(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccessStatus(w, r, h.respWriter, http.StatusCreated, resp)
}

// UnsealBarrier handles POST /api/v1/tenants/{id}/barrier/unseal.
func (h *Handlers) UnsealBarrier(w http.ResponseWriter, r *http.Request) {
	if !h.ensure(w, r) {
		return
	}
	req := &platformv1.UnsealTenantBarrierRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	req.TenantId = mux.Vars(r)["id"]
	resp, err := h.server.UnsealTenantBarrier(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// SealBarrier handles POST /api/v1/tenants/{id}/barrier/seal.
func (h *Handlers) SealBarrier(w http.ResponseWriter, r *http.Request) {
	if !h.ensure(w, r) {
		return
	}
	resp, err := h.server.SealTenantBarrier(r.Context(), &platformv1.SealTenantBarrierRequest{TenantId: mux.Vars(r)["id"]})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// GetBarrierStatus handles GET /api/v1/tenants/{id}/barrier.
func (h *Handlers) GetBarrierStatus(w http.ResponseWriter, r *http.Request) {
	if !h.ensure(w, r) {
		return
	}
	resp, err := h.server.GetTenantBarrierStatus(r.Context(), &platformv1.GetTenantBarrierStatusRequest{TenantId: mux.Vars(r)["id"]})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}
