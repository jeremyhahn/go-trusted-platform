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

package vtpm

// Runtime operations on a bundle: start, stop, state, quote, seal, unseal and
// PCR extend / read. Each handler calls the same vtpm.VTPMService the gRPC and
// QUIC transports call. The replies carry the platformv1 response field names
// (snake_case, bytes base64) so the SDK REST transport decodes them straight
// into the pb reply.

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/restwire"
)

// runtimeErrorStatus maps the vTPM service's typed runtime errors to the HTTP
// status docs/vtpm/api.md §7 gives them. Errors not listed fall through to
// handleServiceError.
var runtimeErrorStatus = []struct {
	matches func(error) bool
	status  int
}{
	{isError[vtpm.ErrBundleNotFound], http.StatusNotFound},
	{isError[vtpm.ErrVTPMNotRunning], http.StatusConflict},
	{isError[vtpm.ErrVTPMAlreadyRunning], http.StatusConflict},
	{isError[vtpm.ErrInvalidNonce], http.StatusBadRequest},
	{isError[vtpm.ErrInvalidPCRIndex], http.StatusBadRequest},
	{isError[vtpm.ErrSwtpmSocketUnavailable], http.StatusServiceUnavailable},
}

// isError reports whether err, or an error it wraps, is a T.
func isError[T error](err error) bool {
	var target T
	return errors.As(err, &target)
}

// handleRuntimeError writes the status a runtime operation's error maps to.
func (h *VTPMHandlers) handleRuntimeError(w http.ResponseWriter, r *http.Request, err error) {
	for _, entry := range runtimeErrorStatus {
		if entry.matches(err) {
			h.respWriter.Write(w, r, entry.status, restwire.WebServiceResponse{
				Code:  entry.status,
				Error: err.Error(),
			})
			return
		}
	}
	h.handleServiceError(w, r, err)
}

// StartVTPM handles POST /api/v1/vtpm/bundles/{id}/start.
func (h *VTPMHandlers) StartVTPM(w http.ResponseWriter, r *http.Request) {
	id := h.getBundleID(r)
	if id == "" {
		h.respWriter.Error400(w, r, ErrMissingBundleID{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	if err := h.service.Start(ctx, id); err != nil {
		h.handleRuntimeError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, StartResponse{
		Status:     SuccessResponse{Success: true, Message: "vTPM started successfully"},
		BundleID:   id,
		Running:    h.service.IsRunning(id),
		SocketPath: h.service.GetTPMSocketPath(id),
	})
}

// StopVTPM handles POST /api/v1/vtpm/bundles/{id}/stop.
func (h *VTPMHandlers) StopVTPM(w http.ResponseWriter, r *http.Request) {
	id := h.getBundleID(r)
	if id == "" {
		h.respWriter.Error400(w, r, ErrMissingBundleID{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	if err := h.service.Stop(ctx, id); err != nil {
		h.handleRuntimeError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, StopResponse{
		Status:   SuccessResponse{Success: true, Message: "vTPM stopped successfully"},
		BundleID: id,
		Stopped:  !h.service.IsRunning(id),
	})
}

// GetVTPMState handles GET /api/v1/vtpm/bundles/{id}/state.
func (h *VTPMHandlers) GetVTPMState(w http.ResponseWriter, r *http.Request) {
	id := h.getBundleID(r)
	if id == "" {
		h.respWriter.Error400(w, r, ErrMissingBundleID{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	// IsRunning reports false for an unknown id; look the bundle up first
	// so a missing bundle is a 404 rather than "not running".
	if _, err := h.service.GetBundle(ctx, id); err != nil {
		h.handleRuntimeError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, StateResponse{
		BundleID:   id,
		Running:    h.service.IsRunning(id),
		SocketPath: h.service.GetTPMSocketPath(id),
	})
}

// QuoteVTPM handles POST /api/v1/vtpm/bundles/{id}/quote.
func (h *VTPMHandlers) QuoteVTPM(w http.ResponseWriter, r *http.Request) {
	id := h.getBundleID(r)
	if id == "" {
		h.respWriter.Error400(w, r, ErrMissingBundleID{})
		return
	}

	var req QuoteRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	result, err := h.service.Quote(ctx, id, req.Nonce, req.PCRs)
	if err != nil {
		h.handleRuntimeError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, QuoteResponse{
		Status:        SuccessResponse{Success: true, Message: "quote generated successfully"},
		BundleID:      id,
		Quote:         result.Quote,
		Signature:     result.Signature,
		PCRValues:     result.PCRValues,
		HashAlgorithm: result.HashAlgorithm,
	})
}

// SealVTPM handles POST /api/v1/vtpm/bundles/{id}/seal.
func (h *VTPMHandlers) SealVTPM(w http.ResponseWriter, r *http.Request) {
	id := h.getBundleID(r)
	if id == "" {
		h.respWriter.Error400(w, r, ErrMissingBundleID{})
		return
	}

	var req SealRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	sealed, err := h.service.Seal(ctx, id, req.Data, &vtpm.SealOptions{
		PCRs:      req.PCRs,
		AuthValue: req.AuthValue,
	})
	if err != nil {
		h.handleRuntimeError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, SealResponse{
		Status:     SuccessResponse{Success: true, Message: "data sealed successfully"},
		BundleID:   id,
		SealedData: sealed,
	})
}

// UnsealVTPM handles POST /api/v1/vtpm/bundles/{id}/unseal.
func (h *VTPMHandlers) UnsealVTPM(w http.ResponseWriter, r *http.Request) {
	id := h.getBundleID(r)
	if id == "" {
		h.respWriter.Error400(w, r, ErrMissingBundleID{})
		return
	}

	var req UnsealRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	data, err := h.service.Unseal(ctx, id, req.SealedData, req.AuthValue)
	if err != nil {
		h.handleRuntimeError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, UnsealResponse{
		Status:   SuccessResponse{Success: true, Message: "data unsealed successfully"},
		BundleID: id,
		Data:     data,
	})
}

// ExtendVTPMPCR handles POST /api/v1/vtpm/bundles/{id}/pcrs/extend.
func (h *VTPMHandlers) ExtendVTPMPCR(w http.ResponseWriter, r *http.Request) {
	id := h.getBundleID(r)
	if id == "" {
		h.respWriter.Error400(w, r, ErrMissingBundleID{})
		return
	}

	var req ExtendPCRRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	if err := h.service.ExtendPCR(ctx, id, req.PCRIndex, req.Data); err != nil {
		h.handleRuntimeError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, ExtendPCRResponse{
		Status:   SuccessResponse{Success: true, Message: "PCR extended successfully"},
		BundleID: id,
		PCRIndex: req.PCRIndex,
		Extended: true,
	})
}

// ReadVTPMPCR handles GET /api/v1/vtpm/bundles/{id}/pcrs?pcr_index=N. An
// absent pcr_index reads PCR 0, the way the SDK omits a zero index.
func (h *VTPMHandlers) ReadVTPMPCR(w http.ResponseWriter, r *http.Request) {
	id := h.getBundleID(r)
	if id == "" {
		h.respWriter.Error400(w, r, ErrMissingBundleID{})
		return
	}

	pcrIndex, err := parsePCRIndexQuery(r)
	if err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	value, err := h.service.ReadPCR(ctx, id, pcrIndex)
	if err != nil {
		h.handleRuntimeError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, ReadPCRResponse{
		Status:   SuccessResponse{Success: true, Message: "PCR read successfully"},
		BundleID: id,
		PCRIndex: pcrIndex,
		Value:    value,
	})
}

// parsePCRIndexQuery reads the pcr_index query parameter, 0 when absent.
func parsePCRIndexQuery(r *http.Request) (int, error) {
	raw := r.URL.Query().Get("pcr_index")
	if raw == "" {
		return 0, nil
	}
	index, err := strconv.Atoi(raw)
	if err != nil {
		return 0, ErrInvalidPCRIndexQuery{Value: raw}
	}
	return index, nil
}
