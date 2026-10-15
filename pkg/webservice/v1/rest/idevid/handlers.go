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

package idevid

import (
	"net/http"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/internal/protorest"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/restwire"
)

// Handlers serves /api/v1/idevid using the supplied gRPC server impl.
type Handlers struct {
	logger     *logging.Logger
	server     platformv1.IDevIDServiceServer
	respWriter response.HttpWriter
}

// NewHandlers wires the supplied server.
func NewHandlers(
	logger *logging.Logger,
	server platformv1.IDevIDServiceServer,
	respWriter response.HttpWriter,
) *Handlers {
	return &Handlers{logger: logger, server: server, respWriter: respWriter}
}

func (h *Handlers) ensureAvailable(w http.ResponseWriter, r *http.Request) bool {
	if h.server == nil {
		protorest.WriteError(w, r, h.respWriter, &protorest.ErrServiceUnavailable{Service: "idevid"})
		return false
	}
	return true
}

// writeKeyDeleteError answers a failed IDevID or IAK key delete. The
// service's refusal (FailedPrecondition, ErrDeviceIdentityKeyNotDeletable)
// is 412, as on the daemon listener: the SDK's REST transport reads 412 back
// as FailedPrecondition and so returns its typed refusal, where protorest's
// shared 400 (#665) would read as an ordinary failure. Every other error
// takes the shared mapping.
func (h *Handlers) writeKeyDeleteError(w http.ResponseWriter, r *http.Request, err error) {
	if status.Code(err) != codes.FailedPrecondition {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	h.respWriter.Write(w, r, http.StatusPreconditionFailed, restwire.WebServiceResponse{
		Code:    http.StatusPreconditionFailed,
		Error:   err.Error(),
		Success: false,
	})
}

// GenerateIDevID handles POST /api/v1/idevid/generate.
func (h *Handlers) GenerateIDevID(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	req := &platformv1.GenerateIDevIDRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	resp, err := h.server.GenerateIDevID(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccessStatus(w, r, h.respWriter, http.StatusCreated, resp)
}

// GetIDevIDInfo handles GET /api/v1/idevid.
func (h *Handlers) GetIDevIDInfo(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	resp, err := h.server.GetIDevIDInfo(r.Context(), &platformv1.GetIDevIDInfoRequest{})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// HasIDevID handles GET /api/v1/idevid/exists.
func (h *Handlers) HasIDevID(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	resp, err := h.server.HasIDevID(r.Context(), &platformv1.HasIDevIDRequest{})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// GetExpiringIDevIDs handles GET /api/v1/idevid/expiring. Returns a
// minimal `{count}` payload — the WebUI uses this as a sentinel for the
// "certificate expiring soon" banner. The platform daemon does not yet
// expose an enumeration RPC for IDevID expiry windows, so for now the
// handler returns count=0 when the IDevID service is unavailable rather
// than 404'ing the dashboard page.
func (h *Handlers) GetExpiringIDevIDs(w http.ResponseWriter, r *http.Request) {
	// IDevID is single-instance per host; "expiring" reduces to "is the
	// installed certificate within its renewal window?" The daemon's
	// HasIDevID + GetIDevIDInfo are sufficient to answer this once info
	// includes NotAfter. Until that field is plumbed through, surface
	// count=0 so the page renders without the warning banner. We bypass
	// protorest.WriteSuccess here because that helper expects a proto
	// message — this synthetic shape is plain JSON.
	h.respWriter.Success200(w, r, map[string]int{"count": 0})
}

// DeleteIDevID handles DELETE /api/v1/idevid.
func (h *Handlers) DeleteIDevID(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	resp, err := h.server.DeleteIDevID(r.Context(), &platformv1.DeleteIDevIDRequest{})
	if err != nil {
		h.writeKeyDeleteError(w, r, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// GenerateIAK handles POST /api/v1/idevid/iak/generate.
func (h *Handlers) GenerateIAK(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	req := &platformv1.GenerateIAKRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	resp, err := h.server.GenerateIAK(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccessStatus(w, r, h.respWriter, http.StatusCreated, resp)
}

// GetIAKInfo handles GET /api/v1/idevid/iak.
func (h *Handlers) GetIAKInfo(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	resp, err := h.server.GetIAKInfo(r.Context(), &platformv1.GetIAKInfoRequest{})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// HasIAK handles GET /api/v1/idevid/iak/exists.
func (h *Handlers) HasIAK(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	resp, err := h.server.HasIAK(r.Context(), &platformv1.HasIAKRequest{})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// DeleteIAK handles DELETE /api/v1/idevid/iak.
func (h *Handlers) DeleteIAK(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	resp, err := h.server.DeleteIAK(r.Context(), &platformv1.DeleteIAKRequest{})
	if err != nil {
		h.writeKeyDeleteError(w, r, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// CreateIDevIDCSR handles POST /api/v1/idevid/csr.
func (h *Handlers) CreateIDevIDCSR(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	req := &platformv1.CreateIDevIDCSRRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	resp, err := h.server.CreateIDevIDCSR(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// CreateIAKCSR handles POST /api/v1/idevid/iak/csr.
func (h *Handlers) CreateIAKCSR(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	req := &platformv1.CreateIAKCSRRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	resp, err := h.server.CreateIAKCSR(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// CreateLDevID handles POST /api/v1/idevid/ldevid. It creates the LDevID key
// in the TPM and has the platform CA issue its certificate.
func (h *Handlers) CreateLDevID(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	req := &platformv1.CreateLDevIDRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	resp, err := h.server.CreateLDevID(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccessStatus(w, r, h.respWriter, http.StatusCreated, resp)
}

// InstallIDevIDCertificate handles POST /api/v1/idevid/certificate.
func (h *Handlers) InstallIDevIDCertificate(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	req := &platformv1.InstallIDevIDCertificateRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	resp, err := h.server.InstallIDevIDCertificate(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccessStatus(w, r, h.respWriter, http.StatusCreated, resp)
}

// InstallIAKCertificate handles POST /api/v1/idevid/iak/certificate.
func (h *Handlers) InstallIAKCertificate(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	req := &platformv1.InstallIAKCertificateRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	resp, err := h.server.InstallIAKCertificate(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccessStatus(w, r, h.respWriter, http.StatusCreated, resp)
}

// GetIDevIDCertificate handles GET /api/v1/idevid/certificate.
func (h *Handlers) GetIDevIDCertificate(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	resp, err := h.server.GetIDevIDCertificate(r.Context(), &platformv1.GetIDevIDCertificateRequest{})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// GetIAKCertificate handles GET /api/v1/idevid/iak/certificate.
func (h *Handlers) GetIAKCertificate(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	resp, err := h.server.GetIAKCertificate(r.Context(), &platformv1.GetIAKCertificateRequest{})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// DeleteIDevIDCertificate handles DELETE /api/v1/idevid/certificate.
func (h *Handlers) DeleteIDevIDCertificate(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	resp, err := h.server.DeleteIDevIDCertificate(r.Context(), &platformv1.DeleteIDevIDCertificateRequest{})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// DeleteIAKCertificate handles DELETE /api/v1/idevid/iak/certificate.
func (h *Handlers) DeleteIAKCertificate(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	resp, err := h.server.DeleteIAKCertificate(r.Context(), &platformv1.DeleteIAKCertificateRequest{})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// GetDeviceAttributes handles GET /api/v1/idevid/attributes.
func (h *Handlers) GetDeviceAttributes(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	resp, err := h.server.GetDeviceAttributes(r.Context(), &platformv1.GetDeviceAttributesRequest{})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// FlushTransientContexts handles POST /api/v1/idevid/flush.
func (h *Handlers) FlushTransientContexts(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	resp, err := h.server.FlushTransientContexts(r.Context(), &platformv1.FlushTransientContextsRequest{})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// ActivateCredential handles POST /api/v1/idevid/activate-credential.
func (h *Handlers) ActivateCredential(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	req := &platformv1.ActivateCredentialRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	resp, err := h.server.ActivateCredential(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}
