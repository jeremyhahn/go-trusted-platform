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
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// ntpBasePath is the REST prefix for time-synchronization endpoints on the
// daemon's own REST server. It matches the webservice mount so a client sees
// the same URLs regardless of which REST listener it reaches.
const ntpBasePath = "/api/v1/ntp"

// ntpMarshalOptions renders proto messages with the same conventions the
// webservice uses, so both REST listeners emit byte-identical payloads.
var ntpMarshalOptions = protojson.MarshalOptions{
	UseProtoNames:   false,
	EmitUnpopulated: true,
}

// ErrNTPUnavailable is returned when the node has no `ntp:` configuration
// section, which per the platform's explicit-config convention means
// platformd deliberately does not manage time here.
type ErrNTPUnavailable struct{}

// Error implements the error interface.
func (ErrNTPUnavailable) Error() string {
	return "ntp service is not configured on this node"
}

// NTPHandlers binds the time-synchronization REST routes to the in-process
// NTPServiceServer that also backs gRPC, QUIC, MCP, and the Unix socket.
type NTPHandlers struct {
	server platformv1.NTPServiceServer
	logger *slog.Logger
}

// NewNTPHandlers creates the time-synchronization REST handlers. A nil server
// leaves every route returning 503.
func NewNTPHandlers(server platformv1.NTPServiceServer, logger *slog.Logger) *NTPHandlers {
	if logger == nil {
		logger = slog.Default()
	}
	return &NTPHandlers{server: server, logger: logger}
}

// RegisterRoutes mounts the time-synchronization routes.
//
//	GET  /api/v1/ntp/status   - GetStatus
//	GET  /api/v1/ntp/sources  - ListSources
//	POST /api/v1/ntp/step     - Step (operator recovery, ntp:write)
func (h *NTPHandlers) RegisterRoutes(router *mux.Router) {
	router.HandleFunc(ntpBasePath+"/status", h.handleGetStatus).Methods(http.MethodGet)
	router.HandleFunc(ntpBasePath+"/sources", h.handleListSources).Methods(http.MethodGet)
	router.HandleFunc(ntpBasePath+"/step", h.handleStep).Methods(http.MethodPost)
}

// handleGetStatus handles GET /api/v1/ntp/status.
func (h *NTPHandlers) handleGetStatus(w http.ResponseWriter, r *http.Request) {
	if h.server == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrNTPUnavailable{})
		return
	}
	resp, err := h.server.GetStatus(r.Context(), &platformv1.GetNTPStatusRequest{})
	if err != nil {
		h.writeStatusError(w, err)
		return
	}
	h.writeProto(w, http.StatusOK, resp)
}

// handleListSources handles GET /api/v1/ntp/sources.
func (h *NTPHandlers) handleListSources(w http.ResponseWriter, r *http.Request) {
	if h.server == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrNTPUnavailable{})
		return
	}
	resp, err := h.server.ListSources(r.Context(), &platformv1.ListNTPSourcesRequest{})
	if err != nil {
		h.writeStatusError(w, err)
		return
	}
	h.writeProto(w, http.StatusOK, resp)
}

// handleStep handles POST /api/v1/ntp/step. It answers 409 Conflict when no
// source is reachable rather than moving the clock on stale data.
func (h *NTPHandlers) handleStep(w http.ResponseWriter, r *http.Request) {
	if h.server == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrNTPUnavailable{})
		return
	}
	resp, err := h.server.Step(r.Context(), &platformv1.StepNTPClockRequest{})
	if err != nil {
		h.writeStatusError(w, err)
		return
	}
	h.writeProto(w, http.StatusOK, resp)
}

// ntpGRPCToHTTPStatus maps the service's gRPC codes onto HTTP status codes
// (map-based for O(1) lookup). It mirrors the webservice's protorest mapping
// so both REST listeners answer identically.
var ntpGRPCToHTTPStatus = map[codes.Code]int{
	codes.OK:                 http.StatusOK,
	codes.InvalidArgument:    http.StatusBadRequest,
	codes.FailedPrecondition: http.StatusBadRequest,
	codes.Unauthenticated:    http.StatusUnauthorized,
	codes.PermissionDenied:   http.StatusForbidden,
	codes.NotFound:           http.StatusNotFound,
	codes.Aborted:            http.StatusConflict,
	codes.AlreadyExists:      http.StatusConflict,
	codes.Unavailable:        http.StatusServiceUnavailable,
	codes.DeadlineExceeded:   http.StatusGatewayTimeout,
	codes.Unimplemented:      http.StatusNotImplemented,
}

// writeStatusError maps a gRPC status error onto its HTTP equivalent.
func (h *NTPHandlers) writeStatusError(w http.ResponseWriter, err error) {
	code := http.StatusInternalServerError
	if mapped, ok := ntpGRPCToHTTPStatus[status.Code(err)]; ok {
		code = mapped
	}
	h.logger.Error("NTP request failed", "error", err, "http_status", code)
	h.writeError(w, code, err)
}

// writeProto writes a protojson-encoded response body.
func (h *NTPHandlers) writeProto(w http.ResponseWriter, statusCode int, msg proto.Message) {
	payload, err := ntpMarshalOptions.Marshal(msg)
	if err != nil {
		h.logger.Error("Failed to encode NTP response", "error", err)
		h.writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if _, writeErr := w.Write(payload); writeErr != nil {
		h.logger.Error("Failed to write NTP response", "error", writeErr)
	}
}

// writeError writes the standard REST error envelope.
func (h *NTPHandlers) writeError(w http.ResponseWriter, statusCode int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	body := ErrorResponse{
		Error:     err.Error(),
		Code:      statusCode,
		Timestamp: time.Now().UTC(),
	}
	if encodeErr := json.NewEncoder(w).Encode(body); encodeErr != nil {
		h.logger.Error("Failed to encode NTP error response", "error", encodeErr)
	}
}
