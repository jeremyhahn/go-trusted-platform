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

package quic

import (
	"context"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Proxy category (gateway category 0x2F, sub-range 0x20-0x2D) handlers.
//
// All handlers delegate to the ProxyServiceInterface, which is satisfied
// by the daemon's shared ProxyGRPCService, so the typed proxy error ->
// status-code mapping is reused by construction; this file only
// translates the resulting gRPC codes to QUIC status bytes.
//
// Wire format: the QUIC payload codec keys on exact Go field names, so
// requests and responses are the platform.v1 protobuf messages encoded
// directly (the same convention as the EAB and config delivery
// category handlers).

// =============================================================================
// Errors
// =============================================================================

// ErrProxyServiceNotConfigured indicates the proxy service is not wired
// into the QUIC handler.
type ErrProxyServiceNotConfigured struct{}

// Error returns the error message.
func (e ErrProxyServiceNotConfigured) Error() string {
	return "proxy service not configured"
}

// ErrProxyMissingSubOpcode indicates a proxy category request arrived with
// an empty payload (no sub-opcode byte).
type ErrProxyMissingSubOpcode struct{}

// Error returns the error message.
func (e ErrProxyMissingSubOpcode) Error() string {
	return "proxy request missing sub-opcode"
}

// ErrProxyUnknownSubOpcode indicates a proxy category request carried a
// sub-opcode outside the proxy sub-range.
type ErrProxyUnknownSubOpcode struct {
	SubOpcode byte
}

// Error returns the error message.
func (e ErrProxyUnknownSubOpcode) Error() string {
	return "unknown proxy sub-opcode"
}

// ErrProxyDecodingFailed indicates a proxy request payload failed to decode.
type ErrProxyDecodingFailed struct {
	Cause error
}

// Error returns the error message.
func (e ErrProxyDecodingFailed) Error() string {
	return "proxy request decoding failed: " + e.Cause.Error()
}

// Unwrap exposes the underlying cause for errors.Is/As.
func (e ErrProxyDecodingFailed) Unwrap() error {
	return e.Cause
}

// ErrProxyEncodingFailed indicates a proxy response failed to encode.
type ErrProxyEncodingFailed struct {
	Cause error
}

// Error returns the error message.
func (e ErrProxyEncodingFailed) Error() string {
	return "proxy response encoding failed: " + e.Cause.Error()
}

// Unwrap exposes the underlying cause for errors.Is/As.
func (e ErrProxyEncodingFailed) Unwrap() error {
	return e.Cause
}

// =============================================================================
// Service interface
// =============================================================================

// ProxyServiceInterface is the proxy configuration surface the QUIC
// transport delegates to. It is satisfied by the daemon's shared
// ProxyGRPCService, guaranteeing identical semantics and error mapping
// across transports.
type ProxyServiceInterface interface {
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
// ProxyHandler
// =============================================================================

// ProxyHandler handles proxy configuration sub-opcodes multiplexed under
// the gateway category opcode (0x2F, sub-range 0x20-0x2D).
type ProxyHandler struct {
	logger  *logging.Logger
	service ProxyServiceInterface
}

// NewProxyHandler creates a new ProxyHandler.
func NewProxyHandler(logger *logging.Logger, service ProxyServiceInterface) *ProxyHandler {
	if logger == nil {
		logger = logging.DefaultLogger()
	}
	return &ProxyHandler{
		logger:  logger,
		service: service,
	}
}

// proxyQUICHandler handles one proxy sub-operation.
type proxyQUICHandler func(h *ProxyHandler, ctx context.Context, payload []byte) *quicwire.Response

// proxyQUICDispatch routes proxy sub-opcodes with O(1) lookup.
var proxyQUICDispatch = map[byte]proxyQUICHandler{
	quicwire.ProxySubRouteCreate: (*ProxyHandler).handleRouteCreate,
	quicwire.ProxySubRouteGet:    (*ProxyHandler).handleRouteGet,
	quicwire.ProxySubRouteUpdate: (*ProxyHandler).handleRouteUpdate,
	quicwire.ProxySubRouteDelete: (*ProxyHandler).handleRouteDelete,
	quicwire.ProxySubRouteList:   (*ProxyHandler).handleRouteList,
	quicwire.ProxySubPoolCreate:  (*ProxyHandler).handlePoolCreate,
	quicwire.ProxySubPoolGet:     (*ProxyHandler).handlePoolGet,
	quicwire.ProxySubPoolUpdate:  (*ProxyHandler).handlePoolUpdate,
	quicwire.ProxySubPoolDelete:  (*ProxyHandler).handlePoolDelete,
	quicwire.ProxySubPoolList:    (*ProxyHandler).handlePoolList,
	quicwire.ProxySubConfigGet:   (*ProxyHandler).handleConfigGet,
	quicwire.ProxySubStatusGet:   (*ProxyHandler).handleStatusGet,
	quicwire.ProxySubReload:      (*ProxyHandler).handleReload,
	quicwire.ProxySubZoneMatrix:  (*ProxyHandler).handleZoneMatrix,
}

// IsProxySubOpcode reports whether sub belongs to the proxy sub-range under
// the gateway category opcode. The gateway category dispatcher uses this to
// route proxy sub-opcodes to the ProxyHandler before falling through to the
// gateway handler.
func IsProxySubOpcode(sub byte) bool {
	_, ok := proxyQUICDispatch[sub]
	return ok
}

// HandleRequest dispatches a proxy category request. The request Opcode
// carries the sub-opcode (the category dispatcher strips payload[0]).
func (h *ProxyHandler) HandleRequest(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if req == nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrProxyMissingSubOpcode{})
	}
	fn, ok := proxyQUICDispatch[req.Opcode]
	if !ok {
		return h.errorResponse(quicwire.StatusNotImplemented, ErrProxyUnknownSubOpcode{SubOpcode: req.Opcode})
	}
	if h.service == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrProxyServiceNotConfigured{})
	}
	return fn(h, ctx, req.Payload)
}

// errorResponse builds an error response with the given status byte.
func (h *ProxyHandler) errorResponse(statusByte byte, err error) *quicwire.Response {
	return &quicwire.Response{
		Status:  statusByte,
		Payload: []byte(err.Error()),
	}
}

// grpcCodeToQUICStatus maps gRPC codes produced by the shared gRPC services
// (ProxyGRPCService, the gateway service) to QUIC status bytes.
var grpcCodeToQUICStatus = map[codes.Code]byte{
	codes.InvalidArgument:    quicwire.StatusInvalidArgument,
	codes.Unauthenticated:    quicwire.StatusUnauthorized,
	codes.PermissionDenied:   quicwire.StatusPermissionDenied,
	codes.NotFound:           quicwire.StatusNotFound,
	codes.AlreadyExists:      quicwire.StatusAlreadyExists,
	codes.FailedPrecondition: quicwire.StatusInvalidRequest,
	codes.Unavailable:        quicwire.StatusUnavailable,
	codes.Internal:           quicwire.StatusInternalError,
}

// proxyErrorResponse converts a gRPC status error from the shared
// ProxyGRPCService into a QUIC error response, preserving the status-code
// semantics established by the service's mapError table.
func (h *ProxyHandler) proxyErrorResponse(op string, err error) *quicwire.Response {
	quicStatus := quicwire.StatusInternalError
	if mapped, ok := grpcCodeToQUICStatus[status.Code(err)]; ok {
		quicStatus = mapped
	}
	h.logger.Error(err, "proxy QUIC operation failed", "operation", op)
	return h.errorResponse(quicStatus, err)
}

// encodeResponse encodes v as a StatusOK QUIC response.
func (h *ProxyHandler) encodeResponse(v interface{}) *quicwire.Response {
	payload, err := quicwire.EncodePayload(v)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrProxyEncodingFailed{Cause: err})
	}
	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// Sub-operation handlers
// =============================================================================

func (h *ProxyHandler) handleRouteCreate(ctx context.Context, payload []byte) *quicwire.Response {
	var req platformv1.CreateProxyRouteRequest
	if err := quicwire.DecodePayload(payload, &req); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrProxyDecodingFailed{Cause: err})
	}
	resp, err := h.service.CreateRoute(ctx, &req)
	if err != nil {
		return h.proxyErrorResponse("ProxyRouteCreate", err)
	}
	return h.encodeResponse(resp)
}

func (h *ProxyHandler) handleRouteGet(ctx context.Context, payload []byte) *quicwire.Response {
	var req platformv1.GetProxyRouteRequest
	if err := quicwire.DecodePayload(payload, &req); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrProxyDecodingFailed{Cause: err})
	}
	resp, err := h.service.GetRoute(ctx, &req)
	if err != nil {
		return h.proxyErrorResponse("ProxyRouteGet", err)
	}
	return h.encodeResponse(resp)
}

func (h *ProxyHandler) handleRouteUpdate(ctx context.Context, payload []byte) *quicwire.Response {
	var req platformv1.UpdateProxyRouteRequest
	if err := quicwire.DecodePayload(payload, &req); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrProxyDecodingFailed{Cause: err})
	}
	resp, err := h.service.UpdateRoute(ctx, &req)
	if err != nil {
		return h.proxyErrorResponse("ProxyRouteUpdate", err)
	}
	return h.encodeResponse(resp)
}

func (h *ProxyHandler) handleRouteDelete(ctx context.Context, payload []byte) *quicwire.Response {
	var req platformv1.DeleteProxyRouteRequest
	if err := quicwire.DecodePayload(payload, &req); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrProxyDecodingFailed{Cause: err})
	}
	resp, err := h.service.DeleteRoute(ctx, &req)
	if err != nil {
		return h.proxyErrorResponse("ProxyRouteDelete", err)
	}
	return h.encodeResponse(resp)
}

func (h *ProxyHandler) handleRouteList(ctx context.Context, payload []byte) *quicwire.Response {
	var req platformv1.ListProxyRoutesRequest
	if err := quicwire.DecodePayload(payload, &req); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrProxyDecodingFailed{Cause: err})
	}
	resp, err := h.service.ListRoutes(ctx, &req)
	if err != nil {
		return h.proxyErrorResponse("ProxyRouteList", err)
	}
	return h.encodeResponse(resp)
}

func (h *ProxyHandler) handlePoolCreate(ctx context.Context, payload []byte) *quicwire.Response {
	var req platformv1.CreateProxyPoolRequest
	if err := quicwire.DecodePayload(payload, &req); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrProxyDecodingFailed{Cause: err})
	}
	resp, err := h.service.CreatePool(ctx, &req)
	if err != nil {
		return h.proxyErrorResponse("ProxyPoolCreate", err)
	}
	return h.encodeResponse(resp)
}

func (h *ProxyHandler) handlePoolGet(ctx context.Context, payload []byte) *quicwire.Response {
	var req platformv1.GetProxyPoolRequest
	if err := quicwire.DecodePayload(payload, &req); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrProxyDecodingFailed{Cause: err})
	}
	resp, err := h.service.GetPool(ctx, &req)
	if err != nil {
		return h.proxyErrorResponse("ProxyPoolGet", err)
	}
	return h.encodeResponse(resp)
}

func (h *ProxyHandler) handlePoolUpdate(ctx context.Context, payload []byte) *quicwire.Response {
	var req platformv1.UpdateProxyPoolRequest
	if err := quicwire.DecodePayload(payload, &req); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrProxyDecodingFailed{Cause: err})
	}
	resp, err := h.service.UpdatePool(ctx, &req)
	if err != nil {
		return h.proxyErrorResponse("ProxyPoolUpdate", err)
	}
	return h.encodeResponse(resp)
}

func (h *ProxyHandler) handlePoolDelete(ctx context.Context, payload []byte) *quicwire.Response {
	var req platformv1.DeleteProxyPoolRequest
	if err := quicwire.DecodePayload(payload, &req); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrProxyDecodingFailed{Cause: err})
	}
	resp, err := h.service.DeletePool(ctx, &req)
	if err != nil {
		return h.proxyErrorResponse("ProxyPoolDelete", err)
	}
	return h.encodeResponse(resp)
}

func (h *ProxyHandler) handlePoolList(ctx context.Context, payload []byte) *quicwire.Response {
	var req platformv1.ListProxyPoolsRequest
	if err := quicwire.DecodePayload(payload, &req); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrProxyDecodingFailed{Cause: err})
	}
	resp, err := h.service.ListPools(ctx, &req)
	if err != nil {
		return h.proxyErrorResponse("ProxyPoolList", err)
	}
	return h.encodeResponse(resp)
}

func (h *ProxyHandler) handleConfigGet(ctx context.Context, payload []byte) *quicwire.Response {
	var req platformv1.GetProxyConfigRequest
	if err := quicwire.DecodePayload(payload, &req); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrProxyDecodingFailed{Cause: err})
	}
	resp, err := h.service.GetProxyConfig(ctx, &req)
	if err != nil {
		return h.proxyErrorResponse("ProxyConfigGet", err)
	}
	return h.encodeResponse(resp)
}

func (h *ProxyHandler) handleStatusGet(ctx context.Context, payload []byte) *quicwire.Response {
	var req platformv1.GetProxyStatusRequest
	if err := quicwire.DecodePayload(payload, &req); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrProxyDecodingFailed{Cause: err})
	}
	resp, err := h.service.GetProxyStatus(ctx, &req)
	if err != nil {
		return h.proxyErrorResponse("ProxyStatusGet", err)
	}
	return h.encodeResponse(resp)
}

func (h *ProxyHandler) handleReload(ctx context.Context, payload []byte) *quicwire.Response {
	var req platformv1.ReloadProxyConfigRequest
	if err := quicwire.DecodePayload(payload, &req); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrProxyDecodingFailed{Cause: err})
	}
	resp, err := h.service.ReloadProxyConfig(ctx, &req)
	if err != nil {
		return h.proxyErrorResponse("ProxyReload", err)
	}
	return h.encodeResponse(resp)
}

func (h *ProxyHandler) handleZoneMatrix(ctx context.Context, payload []byte) *quicwire.Response {
	var req platformv1.GetProxyZoneMatrixRequest
	if err := quicwire.DecodePayload(payload, &req); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrProxyDecodingFailed{Cause: err})
	}
	resp, err := h.service.GetZoneMatrix(ctx, &req)
	if err != nil {
		return h.proxyErrorResponse("ProxyZoneMatrix", err)
	}
	return h.encodeResponse(resp)
}
