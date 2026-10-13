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
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// vpnBasePath is the REST prefix for the VPN control plane on the daemon's
// own REST server. It matches the webservice mount.
const vpnBasePath = "/api/v1/vpn"

// VPN route scopes; they match the VPNService entries in the gRPC method
// catalog (pkg/api/grpc/method_permissions.go).
const (
	scopeVPNRead  = "vpn:read"
	scopeVPNWrite = "vpn:write"
	scopeVPNAdmin = "vpn:admin"
)

// vpnUnmarshalOptions decodes request bodies; unknown fields are refused so a
// misspelt field is an error rather than a silently dropped setting.
var vpnUnmarshalOptions = protojson.UnmarshalOptions{}

// ErrVPNUnavailable is returned when the daemon has no VPN control plane.
type ErrVPNUnavailable struct{}

// Error implements the error interface.
func (ErrVPNUnavailable) Error() string {
	return "vpn control plane is not configured on this node"
}

// ErrVPNInvalidRequestBody is returned when a request body does not decode.
type ErrVPNInvalidRequestBody struct {
	Cause error
}

// Error implements the error interface.
func (e ErrVPNInvalidRequestBody) Error() string {
	return "invalid vpn request body: " + e.Cause.Error()
}

// Unwrap returns the decode failure.
func (e ErrVPNInvalidRequestBody) Unwrap() error { return e.Cause }

// ErrVPNNameMismatch is returned when a posture-policy body names a different
// policy than the path.
type ErrVPNNameMismatch struct {
	Path string
	Body string
}

// Error implements the error interface.
func (e ErrVPNNameMismatch) Error() string {
	return "posture policy name " + e.Body + " in the body does not match " + e.Path + " in the path"
}

// VPNHandlers binds the VPN control-plane REST routes to the in-process
// VPNServiceServer that also backs gRPC, QUIC, MCP, and the Unix socket.
type VPNHandlers struct {
	server platformv1.VPNServiceServer
	guard  *ScopeGuard
	logger *slog.Logger
}

// NewVPNHandlers creates the VPN REST handlers. Each route requires the
// scope its RPC requires on gRPC; a nil guard refuses every route with 403.
// A nil server leaves every authorized route returning 503.
func NewVPNHandlers(server platformv1.VPNServiceServer, guard *ScopeGuard, logger *slog.Logger) *VPNHandlers {
	if logger == nil {
		logger = slog.Default()
	}
	return &VPNHandlers{server: server, guard: guard, logger: logger}
}

// RegisterRoutes mounts the VPN routes.
//
//	POST   /api/v1/vpn/peers                         - EnrolPeer (vpn:write)
//	GET    /api/v1/vpn/peers?tenant_id=              - ListPeers (vpn:read)
//	DELETE /api/v1/vpn/peers/{device_id}?tenant_id=  - RevokePeer (vpn:write)
//	GET    /api/v1/vpn/status?gateway_id=            - GetStatus (vpn:read)
//	GET    /api/v1/vpn/posture-policies?tenant_id=   - ListPosturePolicies (vpn:admin)
//	GET    /api/v1/vpn/posture-policies/{name}       - GetPosturePolicy (vpn:admin)
//	PUT    /api/v1/vpn/posture-policies/{name}       - SetPosturePolicy (vpn:admin)
//	DELETE /api/v1/vpn/posture-policies/{name}       - DeletePosturePolicy (vpn:admin)
func (h *VPNHandlers) RegisterRoutes(router *mux.Router) {
	router.HandleFunc(vpnBasePath+"/peers", h.guard.Require(scopeVPNWrite, h.handleEnrolPeer)).Methods(http.MethodPost)
	router.HandleFunc(vpnBasePath+"/peers", h.guard.Require(scopeVPNRead, h.handleListPeers)).Methods(http.MethodGet)
	router.HandleFunc(vpnBasePath+"/peers/{device_id}", h.guard.Require(scopeVPNWrite, h.handleRevokePeer)).Methods(http.MethodDelete)
	router.HandleFunc(vpnBasePath+"/status", h.guard.Require(scopeVPNRead, h.handleGetStatus)).Methods(http.MethodGet)
	router.HandleFunc(vpnBasePath+"/posture-policies", h.guard.Require(scopeVPNAdmin, h.handleListPosturePolicies)).Methods(http.MethodGet)
	router.HandleFunc(vpnBasePath+"/posture-policies/{name}", h.guard.Require(scopeVPNAdmin, h.handleGetPosturePolicy)).Methods(http.MethodGet)
	router.HandleFunc(vpnBasePath+"/posture-policies/{name}", h.guard.Require(scopeVPNAdmin, h.handleSetPosturePolicy)).Methods(http.MethodPut)
	router.HandleFunc(vpnBasePath+"/posture-policies/{name}", h.guard.Require(scopeVPNAdmin, h.handleDeletePosturePolicy)).Methods(http.MethodDelete)
}

func (h *VPNHandlers) handleEnrolPeer(w http.ResponseWriter, r *http.Request) {
	if !h.requireServer(w) {
		return
	}
	peer := &platformv1.VPNPeer{}
	if !h.decodeBody(w, r, peer) {
		return
	}
	resp, err := h.server.EnrolPeer(r.Context(), &platformv1.EnrolVPNPeerRequest{Peer: peer})
	h.respond(w, http.StatusCreated, resp, err)
}

func (h *VPNHandlers) handleListPeers(w http.ResponseWriter, r *http.Request) {
	if !h.requireServer(w) {
		return
	}
	resp, err := h.server.ListPeers(r.Context(), &platformv1.ListVPNPeersRequest{
		TenantId: r.URL.Query().Get("tenant_id"),
	})
	h.respond(w, http.StatusOK, resp, err)
}

func (h *VPNHandlers) handleRevokePeer(w http.ResponseWriter, r *http.Request) {
	if !h.requireServer(w) {
		return
	}
	resp, err := h.server.RevokePeer(r.Context(), &platformv1.RevokeVPNPeerRequest{
		TenantId: r.URL.Query().Get("tenant_id"),
		DeviceId: mux.Vars(r)["device_id"],
	})
	h.respond(w, http.StatusOK, resp, err)
}

func (h *VPNHandlers) handleGetStatus(w http.ResponseWriter, r *http.Request) {
	if !h.requireServer(w) {
		return
	}
	resp, err := h.server.GetStatus(r.Context(), &platformv1.GetVPNStatusRequest{
		GatewayId: r.URL.Query().Get("gateway_id"),
	})
	h.respond(w, http.StatusOK, resp, err)
}

func (h *VPNHandlers) handleListPosturePolicies(w http.ResponseWriter, r *http.Request) {
	if !h.requireServer(w) {
		return
	}
	resp, err := h.server.ListPosturePolicies(r.Context(), &platformv1.ListVPNPosturePoliciesRequest{
		TenantId: r.URL.Query().Get("tenant_id"),
	})
	h.respond(w, http.StatusOK, resp, err)
}

func (h *VPNHandlers) handleGetPosturePolicy(w http.ResponseWriter, r *http.Request) {
	if !h.requireServer(w) {
		return
	}
	resp, err := h.server.GetPosturePolicy(r.Context(), &platformv1.GetVPNPosturePolicyRequest{
		TenantId: r.URL.Query().Get("tenant_id"),
		Name:     mux.Vars(r)["name"],
	})
	h.respond(w, http.StatusOK, resp, err)
}

// handleSetPosturePolicy takes the policy name from the path and the tenant
// and module from the body. A body that names another policy is refused.
func (h *VPNHandlers) handleSetPosturePolicy(w http.ResponseWriter, r *http.Request) {
	if !h.requireServer(w) {
		return
	}
	policy := &platformv1.VPNPosturePolicy{}
	if !h.decodeBody(w, r, policy) {
		return
	}
	name := mux.Vars(r)["name"]
	if policy.GetName() != "" && policy.GetName() != name {
		h.writeError(w, http.StatusBadRequest, ErrVPNNameMismatch{Path: name, Body: policy.GetName()})
		return
	}
	policy.Name = name
	resp, err := h.server.SetPosturePolicy(r.Context(), &platformv1.SetVPNPosturePolicyRequest{Policy: policy})
	h.respond(w, http.StatusOK, resp, err)
}

func (h *VPNHandlers) handleDeletePosturePolicy(w http.ResponseWriter, r *http.Request) {
	if !h.requireServer(w) {
		return
	}
	resp, err := h.server.DeletePosturePolicy(r.Context(), &platformv1.DeleteVPNPosturePolicyRequest{
		TenantId: r.URL.Query().Get("tenant_id"),
		Name:     mux.Vars(r)["name"],
	})
	h.respond(w, http.StatusOK, resp, err)
}

// requireServer writes 503 and returns false when no service is wired.
func (h *VPNHandlers) requireServer(w http.ResponseWriter) bool {
	if h.server == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrVPNUnavailable{})
		return false
	}
	return true
}

// decodeBody decodes a required protojson request body.
func (h *VPNHandlers) decodeBody(w http.ResponseWriter, r *http.Request, msg proto.Message) bool {
	data, err := io.ReadAll(r.Body)
	if err == nil {
		err = vpnUnmarshalOptions.Unmarshal(data, msg)
	}
	if err != nil {
		h.writeError(w, http.StatusBadRequest, ErrVPNInvalidRequestBody{Cause: err})
		return false
	}
	return true
}

// respond writes the service result: the protojson body on success, the
// mapped HTTP status otherwise.
func (h *VPNHandlers) respond(w http.ResponseWriter, successCode int, msg proto.Message, err error) {
	if err != nil {
		code := http.StatusInternalServerError
		if mapped, ok := protorestHTTPStatus[status.Code(err)]; ok {
			code = mapped
		}
		h.logger.Error("VPN request failed", "error", err, "http_status", code)
		h.writeError(w, code, err)
		return
	}
	payload, err := webserviceMarshalOptions.Marshal(msg)
	if err != nil {
		h.logger.Error("Failed to encode VPN response", "error", err)
		h.writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(successCode)
	if _, writeErr := w.Write(payload); writeErr != nil {
		h.logger.Error("Failed to write VPN response", "error", writeErr)
	}
}

// writeError writes the standard REST error envelope.
func (h *VPNHandlers) writeError(w http.ResponseWriter, statusCode int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	body := ErrorResponse{
		Error:     err.Error(),
		Code:      statusCode,
		Timestamp: time.Now().UTC(),
	}
	if encodeErr := json.NewEncoder(w).Encode(body); encodeErr != nil {
		h.logger.Error("Failed to write VPN error response", "error", encodeErr)
	}
}
