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

package daemon

import (
	"encoding/json"
	"net/http"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// registerLDevIDRoutes registers the LDevID (IEEE 802.1AR) REST endpoint. It
// is invoked from registerIDevIDRoutes so the route is mounted alongside the
// IDevID/IAK surface. The path matches the SDK REST adapter mapping for
// /platform.v1.IDevIDService/CreateLDevID so a REST-transport SDK client
// reaches the same handler.
func (s *RESTServer) registerLDevIDRoutes() {
	api := s.router.PathPrefix(restBasePath).Subrouter()
	api.HandleFunc("/idevid/ldevid", s.handleLDevIDCreate).Methods(http.MethodPost)
	s.logger.Info("LDevID REST route registered", "path", restBasePath+"/idevid/ldevid")
}

// handleLDevIDCreate handles POST /api/v1/idevid/ldevid.
//
// The request/response bodies are the JSON encodings of the pb
// platformv1.CreateLDevIDRequest / CreateLDevIDResponse messages, so the
// REST transport is wire-symmetric with the SDK REST adapter (which marshals
// the same pb request and decodes the same pb response). The handler adds no
// LDevID logic: it decodes, delegates to the shared
// IDevIDGRPCService.CreateLDevID, and maps the gRPC status error class onto
// the matching HTTP status.
func (s *RESTServer) handleLDevIDCreate(w http.ResponseWriter, r *http.Request) {
	if s.idevidService == nil {
		s.writeError(w, http.StatusServiceUnavailable, ErrLDevIDServiceNotConfigured{})
		return
	}

	var req platformv1.CreateLDevIDRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	resp, err := s.idevidService.CreateLDevID(r.Context(), &req)
	if err != nil {
		s.logger.Error("Failed to issue LDevID over REST", "error", err)
		s.writeError(w, ldevidGRPCToHTTPStatus(err), err)
		return
	}

	s.logger.Info("LDevID certificate issued over REST")
	s.writeJSON(w, http.StatusOK, resp)
}
