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

package configdelivery

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// RestHandler defines the config delivery REST endpoint interface.
type RestHandler interface {
	// GetNonce issues a new nonce for replay prevention.
	// GET /api/v1/provision/nonce
	GetNonce(w http.ResponseWriter, r *http.Request)

	// FetchConfig authenticates and resolves a device configuration.
	// POST /api/v1/provision/config
	FetchConfig(w http.ResponseWriter, r *http.Request)

	// PollSession checks if a pending session has been fulfilled.
	// GET /api/v1/provision/sessions/{sessionID}/poll
	PollSession(w http.ResponseWriter, r *http.Request)

	// FulfillSession links a profile to a pending session.
	// POST /api/v1/provision/sessions/{sessionID}/fulfill
	FulfillSession(w http.ResponseWriter, r *http.Request)

	// ListSessions returns all active provisioning sessions.
	// GET /api/v1/provision/sessions
	ListSessions(w http.ResponseWriter, r *http.Request)

	// GetSession returns a session by ID.
	// GET /api/v1/provision/sessions/{sessionID}
	GetSession(w http.ResponseWriter, r *http.Request)
}

// HandlerParams contains the dependencies for creating a config delivery handler.
type HandlerParams struct {
	Service        *Service
	ResponseWriter response.HttpWriter
	Logger         *logging.Logger
}

// handler implements the RestHandler interface.
type handler struct {
	service        *Service
	responseWriter response.HttpWriter
	logger         *logging.Logger
}

// NewHandler creates a new config delivery REST handler.
func NewHandler(params HandlerParams) (RestHandler, error) {
	if params.Logger == nil {
		return nil, ErrMissingLogger{}
	}
	if params.Service == nil {
		return nil, ErrMissingService{}
	}
	if params.ResponseWriter == nil {
		return nil, ErrMissingResponseWriter{}
	}

	return &handler{
		service:        params.Service,
		responseWriter: params.ResponseWriter,
		logger:         params.Logger,
	}, nil
}

// GetNonce issues a new nonce for replay prevention.
func (h *handler) GetNonce(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("configdelivery: get nonce request received")

	nonce, err := h.service.IssueNonce()
	if err != nil {
		h.responseWriter.Error500(w, r, err)
		return
	}

	h.responseWriter.Success200(w, r, NonceResponse{Nonce: nonce})
}

// FetchConfig authenticates and resolves a device configuration.
func (h *handler) FetchConfig(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("configdelivery: fetch config request received")

	var req ConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.responseWriter.Error400(w, r, ErrInvalidRequest{Reason: err.Error()})
		return
	}

	configResp, pendingResp, err := h.service.ResolveConfig(r.Context(), &req)
	if err != nil {
		h.writeFetchConfigError(w, r, err)
		return
	}

	if pendingResp != nil {
		h.responseWriter.Success200(w, r, pendingResp)
		return
	}

	h.responseWriter.Success200(w, r, configResp)
}

// PollSession checks if a pending session has been fulfilled.
func (h *handler) PollSession(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("configdelivery: poll session request received")

	vars := mux.Vars(r)
	sessionID := vars["sessionID"]
	if sessionID == "" {
		h.responseWriter.Error400(w, r, ErrInvalidRequest{Reason: "session_id is required"})
		return
	}

	configResp, err := h.service.PollSession(r.Context(), sessionID)
	if err != nil {
		h.writeSessionError(w, r, err)
		return
	}

	if configResp == nil {
		h.responseWriter.Success200(w, r, PollPendingResponse{Status: "pending"})
		return
	}

	h.responseWriter.Success200(w, r, configResp)
}

// FulfillSession links a profile to a pending session.
func (h *handler) FulfillSession(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("configdelivery: fulfill session request received")

	var req FulfillRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.responseWriter.Error400(w, r, ErrInvalidRequest{Reason: err.Error()})
		return
	}

	vars := mux.Vars(r)
	sessionID := vars["sessionID"]
	if sessionID == "" {
		sessionID = req.SessionID
	}
	if sessionID == "" {
		h.responseWriter.Error400(w, r, ErrInvalidRequest{Reason: "session_id is required"})
		return
	}

	if err := h.service.FulfillSession(r.Context(), sessionID, req.ProfileID); err != nil {
		h.writeSessionError(w, r, err)
		return
	}

	h.responseWriter.Success200(w, r, map[string]string{"status": "fulfilled"})
}

// ListSessions returns all active provisioning sessions.
func (h *handler) ListSessions(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("configdelivery: list sessions request received")

	sessions := h.service.ListSessions()
	h.responseWriter.Success200(w, r, sessions)
}

// GetSession returns a session by ID.
func (h *handler) GetSession(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("configdelivery: get session request received")

	vars := mux.Vars(r)
	sessionID := vars["sessionID"]
	if sessionID == "" {
		h.responseWriter.Error400(w, r, ErrInvalidRequest{Reason: "session_id is required"})
		return
	}

	session, err := h.service.GetSession(sessionID)
	if err != nil {
		h.writeSessionError(w, r, err)
		return
	}

	h.responseWriter.Success200(w, r, session)
}

// writeFetchConfigError maps service errors to HTTP status codes for config fetch.
func (h *handler) writeFetchConfigError(w http.ResponseWriter, r *http.Request, err error) {
	var invalidReq ErrInvalidRequest
	var nonceRequired ErrNonceRequired
	var nonceExpired ErrNonceExpired

	if errors.As(err, &invalidReq) || errors.As(err, &nonceRequired) {
		h.responseWriter.Error400(w, r, err)
		return
	}

	if errors.As(err, &nonceExpired) {
		h.responseWriter.Error400(w, r, err)
		return
	}

	var eabFailed ErrEABValidationFailed
	if errors.As(err, &eabFailed) {
		h.responseWriter.Error401(w, r, err)
		return
	}

	h.logger.Errorf("configdelivery: fetch config error: %v", err)
	h.responseWriter.Error500(w, r, err)
}

// writeSessionError maps service errors to HTTP status codes for session operations.
func (h *handler) writeSessionError(w http.ResponseWriter, r *http.Request, err error) {
	var notFound ErrSessionNotFound
	var profileNotFound ErrProfileNotFound
	if errors.As(err, &notFound) || errors.As(err, &profileNotFound) {
		h.responseWriter.Error404(w, r, err)
		return
	}

	var expired ErrSessionExpired
	if errors.As(err, &expired) {
		h.responseWriter.Error400(w, r, err)
		return
	}

	var fulfilled ErrSessionAlreadyFulfilled
	if errors.As(err, &fulfilled) {
		h.responseWriter.Error400(w, r, err)
		return
	}

	h.logger.Errorf("configdelivery: session error: %v", err)
	h.responseWriter.Error500(w, r, err)
}

// Ensure handler implements RestHandler interface.
var _ RestHandler = (*handler)(nil)
