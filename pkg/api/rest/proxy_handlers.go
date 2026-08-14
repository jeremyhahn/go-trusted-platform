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
	"encoding/json"
	"io"
	"log/slog"
	"net/http"

	"github.com/gorilla/mux"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// Proxy REST handlers.
//
// The handlers delegate to the ProxyServiceBackend, which is satisfied by
// the daemon's shared ProxyGRPCService, so the typed proxy error ->
// status-code mapping is reused by construction; this file only translates
// the resulting gRPC codes to HTTP statuses. Requests decode and responses
// encode via protojson so the SDK REST transport round-trips the
// platform.v1 messages losslessly (uint64 values travel as JSON strings
// per protojson and repo convention).

// =============================================================================
// Errors
// =============================================================================

// ErrProxyServiceNotAvailable is returned when the proxy service is not
// configured or unavailable.
type ErrProxyServiceNotAvailable struct{}

func (e ErrProxyServiceNotAvailable) Error() string {
	return "proxy service not available"
}

// ErrProxyInvalidRequestBody is returned when a proxy request body cannot
// be decoded.
type ErrProxyInvalidRequestBody struct {
	Cause error
}

func (e ErrProxyInvalidRequestBody) Error() string {
	return "invalid proxy request body: " + e.Cause.Error()
}

// Unwrap exposes the underlying cause for errors.Is/As.
func (e ErrProxyInvalidRequestBody) Unwrap() error {
	return e.Cause
}

// ErrProxyMissingID is returned when a route or pool ID path segment is
// required but empty.
type ErrProxyMissingID struct{}

func (e ErrProxyMissingID) Error() string {
	return "proxy resource id is required"
}

// =============================================================================
// Service interface
// =============================================================================

// ProxyServiceBackend is the proxy configuration surface the REST transport
// delegates to. It is satisfied by the daemon's shared ProxyGRPCService,
// guaranteeing identical semantics and error mapping across transports.
type ProxyServiceBackend interface {
	CreateRoute(ctx context.Context, req *platformv1.CreateProxyRouteRequest) (*platformv1.CreateProxyRouteResponse, error)
	GetRoute(ctx context.Context, req *platformv1.GetProxyRouteRequest) (*platformv1.GetProxyRouteResponse, error)
	UpdateRoute(ctx context.Context, req *platformv1.UpdateProxyRouteRequest) (*platformv1.UpdateProxyRouteResponse, error)
	DeleteRoute(ctx context.Context, req *platformv1.DeleteProxyRouteRequest) (*platformv1.DeleteProxyRouteResponse, error)
	ListRoutes(ctx context.Context, req *platformv1.ListProxyRoutesRequest) (*platformv1.ListProxyRoutesResponse, error)
	CreatePool(ctx context.Context, req *platformv1.CreateProxyPoolRequest) (*platformv1.CreateProxyPoolResponse, error)
	GetPool(ctx context.Context, req *platformv1.GetProxyPoolRequest) (*platformv1.GetProxyPoolResponse, error)
	UpdatePool(ctx context.Context, req *platformv1.UpdateProxyPoolRequest) (*platformv1.UpdateProxyPoolResponse, error)
	DeletePool(ctx context.Context, req *platformv1.DeleteProxyPoolRequest) (*platformv1.DeleteProxyPoolResponse, error)
	ListPools(ctx context.Context, req *platformv1.ListProxyPoolsRequest) (*platformv1.ListProxyPoolsResponse, error)
	GetProxyConfig(ctx context.Context, req *platformv1.GetProxyConfigRequest) (*platformv1.GetProxyConfigResponse, error)
	GetProxyStatus(ctx context.Context, req *platformv1.GetProxyStatusRequest) (*platformv1.GetProxyStatusResponse, error)
	ReloadProxyConfig(ctx context.Context, req *platformv1.ReloadProxyConfigRequest) (*platformv1.ReloadProxyConfigResponse, error)
	GetZoneMatrix(ctx context.Context, req *platformv1.GetProxyZoneMatrixRequest) (*platformv1.GetProxyZoneMatrixResponse, error)
}

// =============================================================================
// ProxyHandlers
// =============================================================================

// proxyMarshalOptions serializes protobuf responses. Field names use the
// proto-json camelCase form and unpopulated fields are emitted so response
// shapes stay stable for clients.
var proxyMarshalOptions = protojson.MarshalOptions{
	EmitUnpopulated: true,
}

// proxyUnmarshalOptions decodes JSON request bodies into protobuf request
// messages. Unknown fields are discarded for forward compatibility.
var proxyUnmarshalOptions = protojson.UnmarshalOptions{
	DiscardUnknown: true,
}

// ProxyHandlers provides REST API handlers for reverse-proxy configuration
// operations.
type ProxyHandlers struct {
	service ProxyServiceBackend
	logger  *slog.Logger
}

// NewProxyHandlers creates a new ProxyHandlers instance.
func NewProxyHandlers(service ProxyServiceBackend, logger *slog.Logger) *ProxyHandlers {
	if logger == nil {
		logger = slog.Default()
	}
	return &ProxyHandlers{
		service: service,
		logger:  logger,
	}
}

// RegisterRoutes registers all proxy routes on the provided router.
func (h *ProxyHandlers) RegisterRoutes(router *mux.Router) {
	// Route CRUD
	router.HandleFunc("/api/v1/proxy/routes", h.handleCreateRoute).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/proxy/routes", h.handleListRoutes).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/proxy/routes/{id}", h.handleGetRoute).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/proxy/routes/{id}", h.handleUpdateRoute).Methods(http.MethodPut)
	router.HandleFunc("/api/v1/proxy/routes/{id}", h.handleDeleteRoute).Methods(http.MethodDelete)

	// Pool CRUD
	router.HandleFunc("/api/v1/proxy/pools", h.handleCreatePool).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/proxy/pools", h.handleListPools).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/proxy/pools/{id}", h.handleGetPool).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/proxy/pools/{id}", h.handleUpdatePool).Methods(http.MethodPut)
	router.HandleFunc("/api/v1/proxy/pools/{id}", h.handleDeletePool).Methods(http.MethodDelete)

	// Config / status / reload / zone matrix
	router.HandleFunc("/api/v1/proxy/config", h.handleGetConfig).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/proxy/status", h.handleGetStatus).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/proxy/reload", h.handleReload).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/proxy/zone-matrix", h.handleZoneMatrix).Methods(http.MethodGet)

	h.logger.Info("Proxy REST routes registered")
}

// =============================================================================
// Helpers
// =============================================================================

// requireService writes 503 and returns false when no backend is wired.
func (h *ProxyHandlers) requireService(w http.ResponseWriter) bool {
	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrProxyServiceNotAvailable{})
		return false
	}
	return true
}

// decodeBody decodes the request body into msg via protojson. Empty bodies
// leave msg zero-valued.
func (h *ProxyHandlers) decodeBody(w http.ResponseWriter, r *http.Request, msg proto.Message) bool {
	if r.Body == nil {
		return true
	}
	data, err := io.ReadAll(r.Body)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, ErrProxyInvalidRequestBody{Cause: err})
		return false
	}
	if len(data) == 0 {
		return true
	}
	if err := proxyUnmarshalOptions.Unmarshal(data, msg); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrProxyInvalidRequestBody{Cause: err})
		return false
	}
	return true
}

// writeProto writes msg as protojson with the given HTTP status.
func (h *ProxyHandlers) writeProto(w http.ResponseWriter, statusCode int, msg proto.Message) {
	payload, err := proxyMarshalOptions.Marshal(msg)
	if err != nil {
		h.logger.Error("Failed to marshal proxy response", "error", err)
		h.writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if _, err := w.Write(payload); err != nil {
		h.logger.Error("Failed to write proxy response", "error", err)
	}
}

// proxyErrorEnvelope is the JSON error body shape for proxy REST errors.
type proxyErrorEnvelope struct {
	Error string `json:"error"`
}

// writeError writes a JSON error envelope.
func (h *ProxyHandlers) writeError(w http.ResponseWriter, statusCode int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if encErr := json.NewEncoder(w).Encode(proxyErrorEnvelope{Error: err.Error()}); encErr != nil {
		h.logger.Error("Failed to write proxy error response", "error", encErr)
	}
}

// proxyGRPCCodeToHTTPStatus maps gRPC codes produced by the shared
// ProxyGRPCService to HTTP statuses.
var proxyGRPCCodeToHTTPStatus = map[codes.Code]int{
	codes.InvalidArgument:    http.StatusBadRequest,
	codes.NotFound:           http.StatusNotFound,
	codes.AlreadyExists:      http.StatusConflict,
	codes.FailedPrecondition: http.StatusConflict,
	codes.Unauthenticated:    http.StatusUnauthorized,
	codes.PermissionDenied:   http.StatusForbidden,
	codes.Unavailable:        http.StatusServiceUnavailable,
	codes.Internal:           http.StatusInternalServerError,
}

// writeServiceError translates a gRPC status error from the shared proxy
// service into an HTTP error response.
func (h *ProxyHandlers) writeServiceError(w http.ResponseWriter, operation string, err error) {
	httpStatus := http.StatusInternalServerError
	if mapped, ok := proxyGRPCCodeToHTTPStatus[status.Code(err)]; ok {
		httpStatus = mapped
	}
	h.logger.Error("Proxy operation failed", "operation", operation, "error", err)
	h.writeError(w, httpStatus, err)
}

// pathID extracts the {id} path variable.
func pathID(r *http.Request) string {
	return mux.Vars(r)["id"]
}

// =============================================================================
// Route handlers
// =============================================================================

// handleCreateRoute handles POST /api/v1/proxy/routes.
func (h *ProxyHandlers) handleCreateRoute(w http.ResponseWriter, r *http.Request) {
	if !h.requireService(w) {
		return
	}
	var req platformv1.CreateProxyRouteRequest
	if !h.decodeBody(w, r, &req) {
		return
	}
	resp, err := h.service.CreateRoute(r.Context(), &req)
	if err != nil {
		h.writeServiceError(w, "create_route", err)
		return
	}
	h.writeProto(w, http.StatusCreated, resp)
}

// handleListRoutes handles GET /api/v1/proxy/routes.
func (h *ProxyHandlers) handleListRoutes(w http.ResponseWriter, r *http.Request) {
	if !h.requireService(w) {
		return
	}
	resp, err := h.service.ListRoutes(r.Context(), &platformv1.ListProxyRoutesRequest{})
	if err != nil {
		h.writeServiceError(w, "list_routes", err)
		return
	}
	h.writeProto(w, http.StatusOK, resp)
}

// handleGetRoute handles GET /api/v1/proxy/routes/{id}.
func (h *ProxyHandlers) handleGetRoute(w http.ResponseWriter, r *http.Request) {
	if !h.requireService(w) {
		return
	}
	id := pathID(r)
	if id == "" {
		h.writeError(w, http.StatusBadRequest, ErrProxyMissingID{})
		return
	}
	resp, err := h.service.GetRoute(r.Context(), &platformv1.GetProxyRouteRequest{Id: id})
	if err != nil {
		h.writeServiceError(w, "get_route", err)
		return
	}
	h.writeProto(w, http.StatusOK, resp)
}

// handleUpdateRoute handles PUT /api/v1/proxy/routes/{id}. The route ID is
// taken from the URL; the body carries the route definition.
func (h *ProxyHandlers) handleUpdateRoute(w http.ResponseWriter, r *http.Request) {
	if !h.requireService(w) {
		return
	}
	id := pathID(r)
	if id == "" {
		h.writeError(w, http.StatusBadRequest, ErrProxyMissingID{})
		return
	}
	var req platformv1.UpdateProxyRouteRequest
	if !h.decodeBody(w, r, &req) {
		return
	}
	req.Id = id
	resp, err := h.service.UpdateRoute(r.Context(), &req)
	if err != nil {
		h.writeServiceError(w, "update_route", err)
		return
	}
	h.writeProto(w, http.StatusOK, resp)
}

// handleDeleteRoute handles DELETE /api/v1/proxy/routes/{id}.
func (h *ProxyHandlers) handleDeleteRoute(w http.ResponseWriter, r *http.Request) {
	if !h.requireService(w) {
		return
	}
	id := pathID(r)
	if id == "" {
		h.writeError(w, http.StatusBadRequest, ErrProxyMissingID{})
		return
	}
	resp, err := h.service.DeleteRoute(r.Context(), &platformv1.DeleteProxyRouteRequest{Id: id})
	if err != nil {
		h.writeServiceError(w, "delete_route", err)
		return
	}
	h.writeProto(w, http.StatusOK, resp)
}

// =============================================================================
// Pool handlers
// =============================================================================

// handleCreatePool handles POST /api/v1/proxy/pools.
func (h *ProxyHandlers) handleCreatePool(w http.ResponseWriter, r *http.Request) {
	if !h.requireService(w) {
		return
	}
	var req platformv1.CreateProxyPoolRequest
	if !h.decodeBody(w, r, &req) {
		return
	}
	resp, err := h.service.CreatePool(r.Context(), &req)
	if err != nil {
		h.writeServiceError(w, "create_pool", err)
		return
	}
	h.writeProto(w, http.StatusCreated, resp)
}

// handleListPools handles GET /api/v1/proxy/pools.
func (h *ProxyHandlers) handleListPools(w http.ResponseWriter, r *http.Request) {
	if !h.requireService(w) {
		return
	}
	resp, err := h.service.ListPools(r.Context(), &platformv1.ListProxyPoolsRequest{})
	if err != nil {
		h.writeServiceError(w, "list_pools", err)
		return
	}
	h.writeProto(w, http.StatusOK, resp)
}

// handleGetPool handles GET /api/v1/proxy/pools/{id}.
func (h *ProxyHandlers) handleGetPool(w http.ResponseWriter, r *http.Request) {
	if !h.requireService(w) {
		return
	}
	id := pathID(r)
	if id == "" {
		h.writeError(w, http.StatusBadRequest, ErrProxyMissingID{})
		return
	}
	resp, err := h.service.GetPool(r.Context(), &platformv1.GetProxyPoolRequest{Id: id})
	if err != nil {
		h.writeServiceError(w, "get_pool", err)
		return
	}
	h.writeProto(w, http.StatusOK, resp)
}

// handleUpdatePool handles PUT /api/v1/proxy/pools/{id}. The pool ID is
// taken from the URL; the body carries the pool definition.
func (h *ProxyHandlers) handleUpdatePool(w http.ResponseWriter, r *http.Request) {
	if !h.requireService(w) {
		return
	}
	id := pathID(r)
	if id == "" {
		h.writeError(w, http.StatusBadRequest, ErrProxyMissingID{})
		return
	}
	var req platformv1.UpdateProxyPoolRequest
	if !h.decodeBody(w, r, &req) {
		return
	}
	req.Id = id
	resp, err := h.service.UpdatePool(r.Context(), &req)
	if err != nil {
		h.writeServiceError(w, "update_pool", err)
		return
	}
	h.writeProto(w, http.StatusOK, resp)
}

// handleDeletePool handles DELETE /api/v1/proxy/pools/{id}.
func (h *ProxyHandlers) handleDeletePool(w http.ResponseWriter, r *http.Request) {
	if !h.requireService(w) {
		return
	}
	id := pathID(r)
	if id == "" {
		h.writeError(w, http.StatusBadRequest, ErrProxyMissingID{})
		return
	}
	resp, err := h.service.DeletePool(r.Context(), &platformv1.DeleteProxyPoolRequest{Id: id})
	if err != nil {
		h.writeServiceError(w, "delete_pool", err)
		return
	}
	h.writeProto(w, http.StatusOK, resp)
}

// =============================================================================
// Config / status / reload / zone matrix handlers
// =============================================================================

// handleGetConfig handles GET /api/v1/proxy/config.
func (h *ProxyHandlers) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	if !h.requireService(w) {
		return
	}
	resp, err := h.service.GetProxyConfig(r.Context(), &platformv1.GetProxyConfigRequest{})
	if err != nil {
		h.writeServiceError(w, "get_config", err)
		return
	}
	h.writeProto(w, http.StatusOK, resp)
}

// handleGetStatus handles GET /api/v1/proxy/status.
func (h *ProxyHandlers) handleGetStatus(w http.ResponseWriter, r *http.Request) {
	if !h.requireService(w) {
		return
	}
	resp, err := h.service.GetProxyStatus(r.Context(), &platformv1.GetProxyStatusRequest{})
	if err != nil {
		h.writeServiceError(w, "get_status", err)
		return
	}
	h.writeProto(w, http.StatusOK, resp)
}

// handleReload handles POST /api/v1/proxy/reload.
func (h *ProxyHandlers) handleReload(w http.ResponseWriter, r *http.Request) {
	if !h.requireService(w) {
		return
	}
	resp, err := h.service.ReloadProxyConfig(r.Context(), &platformv1.ReloadProxyConfigRequest{})
	if err != nil {
		h.writeServiceError(w, "reload", err)
		return
	}
	h.writeProto(w, http.StatusOK, resp)
}

// handleZoneMatrix handles GET /api/v1/proxy/zone-matrix.
func (h *ProxyHandlers) handleZoneMatrix(w http.ResponseWriter, r *http.Request) {
	if !h.requireService(w) {
		return
	}
	resp, err := h.service.GetZoneMatrix(r.Context(), &platformv1.GetProxyZoneMatrixRequest{})
	if err != nil {
		h.writeServiceError(w, "zone_matrix", err)
		return
	}
	h.writeProto(w, http.StatusOK, resp)
}
