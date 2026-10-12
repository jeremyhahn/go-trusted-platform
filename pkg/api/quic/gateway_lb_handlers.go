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
	"errors"
	"net"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// Load balancer sentinel errors.
var (
	// ErrGatewayVIPNotFound is returned when a requested VIP does not exist.
	ErrGatewayVIPNotFound = errors.New("VIP not found")

	// ErrGatewayVIPAlreadyExists is returned when adding a VIP that
	// already exists.
	ErrGatewayVIPAlreadyExists = errors.New("VIP already exists")

	// ErrGatewayInvalidVIP is returned for invalid VIP definitions.
	ErrGatewayInvalidVIP = errors.New("invalid VIP definition")

	// ErrGatewayMissingVIPTarget is returned when the protocol, address,
	// or port of a keyed VIP request is missing or invalid.
	ErrGatewayMissingVIPTarget = errors.New("VIP protocol, address, and port are required")
)

// LBBackendSpec is one load-balanced endpoint behind a VIP.
type LBBackendSpec struct {
	Address string `codec:"address"`
	Port    uint16 `codec:"port"`
	Weight  uint16 `codec:"weight,omitempty"`
}

// LBVIPSpec defines a load-balanced virtual IP.
type LBVIPSpec struct {
	Address   string           `codec:"address"`
	Port      uint16           `codec:"port"`
	Protocol  string           `codec:"protocol"`
	Algorithm string           `codec:"algorithm,omitempty"`
	Backends  []*LBBackendSpec `codec:"backends"`
}

// LBBackendInfo reports one backend and its probed health.
type LBBackendInfo struct {
	Backend *LBBackendSpec `codec:"backend"`
	Healthy bool           `codec:"healthy"`
}

// LBVIPInfo is a point-in-time snapshot of one VIP.
type LBVIPInfo struct {
	Address   string           `codec:"address"`
	Port      uint16           `codec:"port"`
	Protocol  string           `codec:"protocol"`
	Algorithm string           `codec:"algorithm"`
	CTZone    uint16           `codec:"ct_zone"`
	GroupID   uint32           `codec:"group_id"`
	Backends  []*LBBackendInfo `codec:"backends"`
}

// LBStatusInfo is a point-in-time snapshot of the load balancer service.
type LBStatusInfo struct {
	Active          bool  `codec:"active"`
	VIPCount        int   `codec:"vip_count"`
	HealthyBackends int   `codec:"healthy_backends"`
	TotalBackends   int   `codec:"total_backends"`
	LastReconcile   int64 `codec:"last_reconcile,omitempty"`
}

// GatewayAddVIPRequest represents a VIP add request.
type GatewayAddVIPRequest struct {
	VIP *LBVIPSpec `codec:"vip"`
}

// GatewayAddVIPResponse represents a VIP add response.
type GatewayAddVIPResponse struct {
	VIP       *LBVIPInfo `codec:"vip"`
	Timestamp int64      `codec:"timestamp"`
}

// GatewayRemoveVIPRequest represents a VIP remove request.
type GatewayRemoveVIPRequest struct {
	Protocol string `codec:"protocol"`
	Address  string `codec:"address"`
	Port     uint16 `codec:"port"`
}

// GatewayRemoveVIPResponse represents a VIP remove response.
type GatewayRemoveVIPResponse struct {
	Success   bool  `codec:"success"`
	Timestamp int64 `codec:"timestamp"`
}

// GatewayGetVIPRequest represents a VIP get request.
type GatewayGetVIPRequest struct {
	Protocol string `codec:"protocol"`
	Address  string `codec:"address"`
	Port     uint16 `codec:"port"`
}

// GatewayGetVIPResponse represents a VIP get response.
type GatewayGetVIPResponse struct {
	VIP       *LBVIPInfo `codec:"vip"`
	Timestamp int64      `codec:"timestamp"`
}

// GatewayListVIPsRequest represents a VIP list request.
type GatewayListVIPsRequest struct{}

// GatewayListVIPsResponse represents a VIP list response.
type GatewayListVIPsResponse struct {
	VIPs      []*LBVIPInfo `codec:"vips"`
	Count     int32        `codec:"count"`
	Timestamp int64        `codec:"timestamp"`
}

// GatewaySetVIPBackendsRequest represents a VIP backend replacement request.
type GatewaySetVIPBackendsRequest struct {
	Protocol string           `codec:"protocol"`
	Address  string           `codec:"address"`
	Port     uint16           `codec:"port"`
	Backends []*LBBackendSpec `codec:"backends"`
}

// GatewaySetVIPBackendsResponse represents a VIP backend replacement response.
type GatewaySetVIPBackendsResponse struct {
	VIP       *LBVIPInfo `codec:"vip"`
	Timestamp int64      `codec:"timestamp"`
}

// GatewayLBStatusRequest represents a load balancer status request.
type GatewayLBStatusRequest struct{}

// GatewayLBStatusResponse represents a load balancer status response.
type GatewayLBStatusResponse struct {
	Status    *LBStatusInfo `codec:"status"`
	Timestamp int64         `codec:"timestamp"`
}

// gatewayLBHandlers dispatches load balancer sub-opcodes (map-based for
// O(1) lookup, matching the proxy handler convention).
var gatewayLBHandlers = map[byte]func(*GatewayHandler, context.Context, *quicwire.Request) *quicwire.Response{
	quicwire.OpGatewayLBAddVIP:         (*GatewayHandler).handleAddVIP,
	quicwire.OpGatewayLBRemoveVIP:      (*GatewayHandler).handleRemoveVIP,
	quicwire.OpGatewayLBGetVIP:         (*GatewayHandler).handleGetVIP,
	quicwire.OpGatewayLBListVIPs:       (*GatewayHandler).handleListVIPs,
	quicwire.OpGatewayLBSetVIPBackends: (*GatewayHandler).handleSetVIPBackends,
	quicwire.OpGatewayLBStatus:         (*GatewayHandler).handleLBStatus,
}

// validVIPTarget reports whether a keyed VIP request carries a usable
// protocol/address/port triple.
func validVIPTarget(protocol, address string, port uint16) bool {
	if protocol == "" || address == "" || port == 0 {
		return false
	}
	return net.ParseIP(address) != nil
}

// handleAddVIP installs a load-balanced virtual IP.
func (h *GatewayHandler) handleAddVIP(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.gatewayService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrGatewayServiceNotAvailable)
	}

	var addReq GatewayAddVIPRequest
	if err := quicwire.DecodePayload(req.Payload, &addReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrGatewayDecodingFailed{Cause: err})
	}
	if addReq.VIP == nil || !validVIPTarget(addReq.VIP.Protocol, addReq.VIP.Address, addReq.VIP.Port) {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrGatewayMissingVIPTarget)
	}

	vip, err := h.gatewayService.AddVIP(ctx, addReq.VIP)
	if err != nil {
		h.logger.Error(err, "failed to add VIP")
		return h.gatewayErrorResponse(err)
	}

	resp := &GatewayAddVIPResponse{VIP: vip, Timestamp: time.Now().Unix()}
	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrGatewayEncodingFailed{Cause: err})
	}
	return &quicwire.Response{Status: quicwire.StatusOK, Payload: payload}
}

// handleRemoveVIP tears down a load-balanced virtual IP.
func (h *GatewayHandler) handleRemoveVIP(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.gatewayService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrGatewayServiceNotAvailable)
	}

	var removeReq GatewayRemoveVIPRequest
	if err := quicwire.DecodePayload(req.Payload, &removeReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrGatewayDecodingFailed{Cause: err})
	}
	if !validVIPTarget(removeReq.Protocol, removeReq.Address, removeReq.Port) {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrGatewayMissingVIPTarget)
	}

	if err := h.gatewayService.RemoveVIP(ctx, removeReq.Protocol, removeReq.Address, removeReq.Port); err != nil {
		h.logger.Error(err, "failed to remove VIP")
		return h.gatewayErrorResponse(err)
	}

	resp := &GatewayRemoveVIPResponse{Success: true, Timestamp: time.Now().Unix()}
	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrGatewayEncodingFailed{Cause: err})
	}
	return &quicwire.Response{Status: quicwire.StatusOK, Payload: payload}
}

// handleGetVIP returns one VIP's status.
func (h *GatewayHandler) handleGetVIP(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.gatewayService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrGatewayServiceNotAvailable)
	}

	var getReq GatewayGetVIPRequest
	if err := quicwire.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrGatewayDecodingFailed{Cause: err})
	}
	if !validVIPTarget(getReq.Protocol, getReq.Address, getReq.Port) {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrGatewayMissingVIPTarget)
	}

	vip, err := h.gatewayService.GetVIP(ctx, getReq.Protocol, getReq.Address, getReq.Port)
	if err != nil {
		h.logger.Error(err, "failed to get VIP")
		return h.gatewayErrorResponse(err)
	}

	resp := &GatewayGetVIPResponse{VIP: vip, Timestamp: time.Now().Unix()}
	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrGatewayEncodingFailed{Cause: err})
	}
	return &quicwire.Response{Status: quicwire.StatusOK, Payload: payload}
}

// handleListVIPs returns every VIP's status.
func (h *GatewayHandler) handleListVIPs(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.gatewayService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrGatewayServiceNotAvailable)
	}

	vips, err := h.gatewayService.ListVIPs(ctx)
	if err != nil {
		h.logger.Error(err, "failed to list VIPs")
		return h.gatewayErrorResponse(err)
	}

	resp := &GatewayListVIPsResponse{
		VIPs:      vips,
		Count:     int32(len(vips)),
		Timestamp: time.Now().Unix(),
	}
	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrGatewayEncodingFailed{Cause: err})
	}
	return &quicwire.Response{Status: quicwire.StatusOK, Payload: payload}
}

// handleSetVIPBackends replaces a VIP's backend set.
func (h *GatewayHandler) handleSetVIPBackends(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.gatewayService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrGatewayServiceNotAvailable)
	}

	var setReq GatewaySetVIPBackendsRequest
	if err := quicwire.DecodePayload(req.Payload, &setReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrGatewayDecodingFailed{Cause: err})
	}
	if !validVIPTarget(setReq.Protocol, setReq.Address, setReq.Port) {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrGatewayMissingVIPTarget)
	}

	vip, err := h.gatewayService.SetVIPBackends(ctx, setReq.Protocol, setReq.Address, setReq.Port, setReq.Backends)
	if err != nil {
		h.logger.Error(err, "failed to set VIP backends")
		return h.gatewayErrorResponse(err)
	}

	resp := &GatewaySetVIPBackendsResponse{VIP: vip, Timestamp: time.Now().Unix()}
	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrGatewayEncodingFailed{Cause: err})
	}
	return &quicwire.Response{Status: quicwire.StatusOK, Payload: payload}
}

// handleLBStatus returns the load balancer service health snapshot.
func (h *GatewayHandler) handleLBStatus(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.gatewayService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrGatewayServiceNotAvailable)
	}

	lbStatus, err := h.gatewayService.LBStatus(ctx)
	if err != nil {
		h.logger.Error(err, "failed to get LB status")
		return h.gatewayErrorResponse(err)
	}

	resp := &GatewayLBStatusResponse{Status: lbStatus, Timestamp: time.Now().Unix()}
	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrGatewayEncodingFailed{Cause: err})
	}
	return &quicwire.Response{Status: quicwire.StatusOK, Payload: payload}
}
