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

package tpm

import (
	"net/http"
	"strconv"

	"github.com/gorilla/mux"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/internal/protorest"
)

// Handlers serves /api/v1/tpm using the supplied gRPC server impl.
type Handlers struct {
	logger     *logging.Logger
	server     platformv1.TPMServiceServer
	respWriter response.HttpWriter
}

// NewHandlers constructs a new Handlers wrapping the supplied server.
func NewHandlers(
	logger *logging.Logger,
	server platformv1.TPMServiceServer,
	respWriter response.HttpWriter,
) *Handlers {
	return &Handlers{logger: logger, server: server, respWriter: respWriter}
}

func (h *Handlers) ensureAvailable(w http.ResponseWriter, r *http.Request) bool {
	if h.server == nil {
		protorest.WriteError(w, r, h.respWriter, &protorest.ErrServiceUnavailable{Service: "tpm"})
		return false
	}
	return true
}

func (h *Handlers) parseIndex(w http.ResponseWriter, r *http.Request) (uint32, bool) {
	raw := mux.Vars(r)["index"]
	v, err := strconv.ParseUint(raw, 0, 32)
	if err != nil {
		h.respWriter.Error400(w, r, &protorest.ErrInvalidQuery{Name: "index", Value: raw, Cause: err})
		return 0, false
	}
	return uint32(v), true
}

// Info handles GET /api/v1/tpm/info.
func (h *Handlers) Info(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	resp, err := h.server.Info(r.Context(), &platformv1.TPMInfoRequest{})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// Provision handles POST /api/v1/tpm/provision.
func (h *Handlers) Provision(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	req := &platformv1.TPMProvisionRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	resp, err := h.server.Provision(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// Clear handles POST /api/v1/tpm/clear.
func (h *Handlers) Clear(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	req := &platformv1.TPMClearRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	resp, err := h.server.Clear(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// CreateEK handles POST /api/v1/tpm/ek.
func (h *Handlers) CreateEK(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	req := &platformv1.CreateEKRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	resp, err := h.server.CreateEK(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccessStatus(w, r, h.respWriter, http.StatusCreated, resp)
}

// GetEK handles GET /api/v1/tpm/ek.
func (h *Handlers) GetEK(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	resp, err := h.server.GetEK(r.Context(), &platformv1.GetEKRequest{})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// DeleteEK handles DELETE /api/v1/tpm/ek.
func (h *Handlers) DeleteEK(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	resp, err := h.server.DeleteEK(r.Context(), &platformv1.DeleteEKRequest{})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// GetEKCertificate handles GET /api/v1/tpm/ek/certificate.
func (h *Handlers) GetEKCertificate(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	resp, err := h.server.GetEKCertificate(r.Context(), &platformv1.GetEKCertificateRequest{})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// ImportEKCertificate handles POST /api/v1/tpm/ek/certificate.
func (h *Handlers) ImportEKCertificate(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	req := &platformv1.ImportEKCertificateRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	resp, err := h.server.ImportEKCertificate(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccessStatus(w, r, h.respWriter, http.StatusCreated, resp)
}

// CreateSRK handles POST /api/v1/tpm/srk.
func (h *Handlers) CreateSRK(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	req := &platformv1.CreateSRKRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	resp, err := h.server.CreateSRK(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccessStatus(w, r, h.respWriter, http.StatusCreated, resp)
}

// GetSRK handles GET /api/v1/tpm/srk[?handle=<hex|decimal>].
//
// The TCG inventory has two SRKs (SSRK at 0x81000001, PlatformSRK
// at 0x81000002); a `?handle=` query parameter selects which one.
// Empty / 0 means the SSRK (back-compat). Hex (0x prefix) and
// decimal forms are both accepted so callers can pass the canonical
// 0x81000002 literal or its decimal equivalent.
func (h *Handlers) GetSRK(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	req := &platformv1.GetSRKRequest{}
	if raw := r.URL.Query().Get("handle"); raw != "" {
		base := 10
		clean := raw
		if len(clean) >= 2 && (clean[:2] == "0x" || clean[:2] == "0X") {
			base = 16
			clean = clean[2:]
		}
		if v, parseErr := strconv.ParseUint(clean, base, 32); parseErr == nil {
			req.Handle = uint32(v)
		} else {
			h.respWriter.Error400(w, r, parseErr)
			return
		}
	}
	resp, err := h.server.GetSRK(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// DeleteSRK handles DELETE /api/v1/tpm/srk.
func (h *Handlers) DeleteSRK(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	resp, err := h.server.DeleteSRK(r.Context(), &platformv1.DeleteSRKRequest{})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// CreateAK handles POST /api/v1/tpm/ak.
func (h *Handlers) CreateAK(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	req := &platformv1.CreateAKRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	resp, err := h.server.CreateAK(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccessStatus(w, r, h.respWriter, http.StatusCreated, resp)
}

// GetAK handles GET /api/v1/tpm/ak.
func (h *Handlers) GetAK(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	resp, err := h.server.GetAK(r.Context(), &platformv1.GetAKRequest{})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// DeleteAK handles DELETE /api/v1/tpm/ak.
func (h *Handlers) DeleteAK(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	resp, err := h.server.DeleteAK(r.Context(), &platformv1.DeleteAKRequest{})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// Seal handles POST /api/v1/tpm/seal.
func (h *Handlers) Seal(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	req := &platformv1.SealRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	resp, err := h.server.Seal(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// Unseal handles POST /api/v1/tpm/unseal.
func (h *Handlers) Unseal(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	req := &platformv1.UnsealRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	resp, err := h.server.Unseal(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// Quote handles POST /api/v1/tpm/quote.
func (h *Handlers) Quote(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	req := &platformv1.QuoteRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	resp, err := h.server.Quote(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// VerifyQuote handles POST /api/v1/tpm/quote/verify.
func (h *Handlers) VerifyQuote(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	req := &platformv1.VerifyQuoteRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	resp, err := h.server.VerifyQuote(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// GetEventLog handles GET /api/v1/tpm/eventlog.
func (h *Handlers) GetEventLog(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	resp, err := h.server.GetEventLog(r.Context(), &platformv1.GetEventLogRequest{})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// GetPCRs handles GET and POST /api/v1/tpm/pcrs. POST takes a JSON
// GetPCRsRequest body with `indices` and `bank` filters; GET returns
// every PCR across every supported bank and lets the caller filter
// client-side (the WebUI's PCR Banks page does this via the bank
// dropdown). The previous version always constructed an empty
// request regardless of payload, which made the WebUI's bank
// dropdown a visual no-op — SHA-1 values rendered under a "SHA-256"
// label, etc.
func (h *Handlers) GetPCRs(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	req := &platformv1.GetPCRsRequest{}
	if r.Method == http.MethodPost && r.ContentLength != 0 {
		if err := protorest.DecodeRequest(r, req); err != nil {
			h.respWriter.Error400(w, r, err)
			return
		}
	}
	resp, err := h.server.GetPCRs(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// DefineNVRAM handles POST /api/v1/tpm/nvram.
func (h *Handlers) DefineNVRAM(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	req := &platformv1.DefineNVRAMRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	resp, err := h.server.DefineNVRAM(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccessStatus(w, r, h.respWriter, http.StatusCreated, resp)
}

// ReadNVRAM handles GET /api/v1/tpm/nvram/{index}.
func (h *Handlers) ReadNVRAM(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	idx, ok := h.parseIndex(w, r)
	if !ok {
		return
	}
	resp, err := h.server.ReadNVRAM(r.Context(), &platformv1.ReadNVRAMRequest{Index: idx})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// WriteNVRAM handles PUT /api/v1/tpm/nvram/{index}.
func (h *Handlers) WriteNVRAM(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	idx, ok := h.parseIndex(w, r)
	if !ok {
		return
	}
	req := &platformv1.WriteNVRAMRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	req.Index = idx
	resp, err := h.server.WriteNVRAM(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// UndefineNVRAM handles DELETE /api/v1/tpm/nvram/{index}.
func (h *Handlers) UndefineNVRAM(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	idx, ok := h.parseIndex(w, r)
	if !ok {
		return
	}
	resp, err := h.server.UndefineNVRAM(r.Context(), &platformv1.UndefineNVRAMRequest{Index: idx})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// GetRandom handles POST /api/v1/tpm/random.
func (h *Handlers) GetRandom(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	req := &platformv1.GetRandomRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	resp, err := h.server.GetRandom(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}
