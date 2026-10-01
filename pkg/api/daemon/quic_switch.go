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
	"context"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	switchmgmt "github.com/jeremyhahn/go-trusted-platform/pkg/switch"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// switchServiceProvider abstracts the switch management service for the QUIC handler.
// This mirrors device.SwitchServiceProvider to avoid an import cycle with the
// webservice package.
type switchServiceProvider interface {
	Manager(name string) (switchmgmt.Manager, error)
}

// Switch QUIC category opcode uses the category pattern (like overlay/gateway).
// The main opcode OpSwitchCategory (0xCC) triggers this handler.
// The first byte of the payload selects the sub-operation.
const (
	OpSwitchCategory = quic.OpSwitchCategory // 0xCC
)

// Switch sub-opcodes within the category payload.
const (
	SubOpSwitchListPorts     = quic.SwitchSubListPorts
	SubOpSwitchGetPortStatus = quic.SwitchSubGetPortStatus
	SubOpSwitchSetPortVLAN   = quic.SwitchSubSetPortVLAN
	SubOpSwitchEnablePort    = quic.SwitchSubEnablePort
	SubOpSwitchDisablePort   = quic.SwitchSubDisablePort
)

// =============================================================================
// Wire contract
// =============================================================================
//
// The SDK QUIC transport adapter routes every SwitchService method to
// OpSwitchCategory (see sdk/go/transport/quic/adapter.go) and encodes the
// generated platform.v1 protobuf request struct directly under the category
// sub-opcode. The daemon therefore decodes the payload into the SAME
// platform.v1 message the SDK sent and encodes the platform.v1 response the
// SDK expects — the protobuf messages ARE the wire contract (identical to the
// device surface). The maximum VLAN ID a single access port may carry.
const switchMaxVLANID = 4094

// =============================================================================
// Service Handler Extension
// =============================================================================

// WithQUICSwitchService sets the switch service for the QUIC handler.
func WithQUICSwitchService(svc switchServiceProvider) QUICServiceHandlerOption {
	return func(h *QUICServiceHandler) {
		h.switchService = svc
	}
}

// SetSwitchService sets the switch service after construction.
func (h *QUICServiceHandler) SetSwitchService(svc switchServiceProvider) {
	h.switchService = svc
}

// =============================================================================
// Handler Implementation
// =============================================================================

// handleSwitchCategory handles switch category opcode (OpSwitchCategory).
// The first byte of the payload is the sub-opcode that maps to a switch operation.
// The remaining payload bytes are the actual request payload for the sub-operation.
func (h *QUICServiceHandler) handleSwitchCategory(ctx context.Context, req *quic.Request) *quic.Response {
	if h.switchService == nil {
		return h.errorResponse(quic.StatusUnavailable, ErrQUICServiceUnavailable{Service: "switch"})
	}

	if len(req.Payload) == 0 {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICMissingField{Field: "sub_opcode"})
	}

	subOpcode := req.Payload[0]
	subPayload := req.Payload[1:]

	subReq := &quic.Request{
		Opcode:  subOpcode,
		Token:   req.Token,
		Payload: subPayload,
	}

	switch subOpcode {
	case SubOpSwitchListPorts:
		return h.handleSwitchListPorts(ctx, subReq)
	case SubOpSwitchGetPortStatus:
		return h.handleSwitchGetPortStatus(ctx, subReq)
	case SubOpSwitchSetPortVLAN:
		return h.handleSwitchSetPortVLAN(ctx, subReq)
	case SubOpSwitchEnablePort:
		return h.handleSwitchEnablePort(ctx, subReq)
	case SubOpSwitchDisablePort:
		return h.handleSwitchDisablePort(ctx, subReq)
	default:
		return h.errorResponse(quic.StatusNotImplemented, ErrQUICUnknownOpcode{Opcode: subOpcode})
	}
}

// handleSwitchListPorts handles the list ports sub-operation.
func (h *QUICServiceHandler) handleSwitchListPorts(ctx context.Context, req *quic.Request) *quic.Response {
	var listReq platformv1.ListSwitchPortsRequest
	if len(req.Payload) > 0 {
		if err := quic.DecodePayload(req.Payload, &listReq); err != nil {
			return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
		}
	}

	if listReq.GetSwitchName() == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "switch_name"})
	}

	mgr, err := h.switchService.Manager(listReq.GetSwitchName())
	if err != nil {
		return h.errorResponse(quic.StatusNotFound, ErrSwitchNotFoundQUIC{Name: listReq.GetSwitchName()})
	}

	ports, err := mgr.ListPorts(ctx)
	if err != nil {
		h.logger.Error(err, "failed to list switch ports", "switch", listReq.GetSwitchName())
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "SwitchListPorts", Cause: err})
	}

	pbPorts := make([]*platformv1.SwitchPortStatus, 0, len(ports))
	for _, p := range ports {
		pbPorts = append(pbPorts, portStatusToPb(p))
	}

	resp := &platformv1.ListSwitchPortsResponse{Ports: pbPorts}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleSwitchGetPortStatus handles the get port status sub-operation.
func (h *QUICServiceHandler) handleSwitchGetPortStatus(ctx context.Context, req *quic.Request) *quic.Response {
	var getReq platformv1.GetSwitchPortStatusRequest
	if err := quic.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if getReq.GetSwitchName() == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "switch_name"})
	}
	if getReq.GetPortName() == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "port_name"})
	}

	mgr, err := h.switchService.Manager(getReq.GetSwitchName())
	if err != nil {
		return h.errorResponse(quic.StatusNotFound, ErrSwitchNotFoundQUIC{Name: getReq.GetSwitchName()})
	}

	portStatus, err := mgr.GetPortStatus(ctx, getReq.GetPortName())
	if err != nil {
		h.logger.Error(err, "failed to get switch port status",
			"switch", getReq.GetSwitchName(), "port", getReq.GetPortName())
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "SwitchGetPortStatus", Cause: err})
	}

	resp := &platformv1.GetSwitchPortStatusResponse{Port: portStatusToPb(portStatus)}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleSwitchSetPortVLAN handles the set port VLAN sub-operation.
func (h *QUICServiceHandler) handleSwitchSetPortVLAN(ctx context.Context, req *quic.Request) *quic.Response {
	var setReq platformv1.SetSwitchPortVLANRequest
	if err := quic.DecodePayload(req.Payload, &setReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if setReq.GetSwitchName() == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "switch_name"})
	}
	if setReq.GetPortName() == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "port_name"})
	}
	if setReq.GetVlanId() == 0 || setReq.GetVlanId() > switchMaxVLANID {
		return h.errorResponse(quic.StatusInvalidArgument, ErrSwitchInvalidVLANID{Value: setReq.GetVlanId()})
	}

	mgr, err := h.switchService.Manager(setReq.GetSwitchName())
	if err != nil {
		return h.errorResponse(quic.StatusNotFound, ErrSwitchNotFoundQUIC{Name: setReq.GetSwitchName()})
	}

	if err := mgr.SetPortVLAN(ctx, setReq.GetPortName(), uint16(setReq.GetVlanId())); err != nil {
		h.logger.Error(err, "failed to set switch port VLAN",
			"switch", setReq.GetSwitchName(), "port", setReq.GetPortName(), "vlan", setReq.GetVlanId())
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "SwitchSetPortVLAN", Cause: err})
	}

	resp := &platformv1.SetSwitchPortVLANResponse{
		Status: &platformv1.Status{Success: true, Message: "port VLAN updated successfully"},
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("set switch port VLAN",
		"switch", setReq.GetSwitchName(), "port", setReq.GetPortName(), "vlan", setReq.GetVlanId())

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleSwitchEnablePort handles the enable port sub-operation.
func (h *QUICServiceHandler) handleSwitchEnablePort(ctx context.Context, req *quic.Request) *quic.Response {
	var enableReq platformv1.EnableSwitchPortRequest
	if err := quic.DecodePayload(req.Payload, &enableReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if enableReq.GetSwitchName() == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "switch_name"})
	}
	if enableReq.GetPortName() == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "port_name"})
	}

	mgr, err := h.switchService.Manager(enableReq.GetSwitchName())
	if err != nil {
		return h.errorResponse(quic.StatusNotFound, ErrSwitchNotFoundQUIC{Name: enableReq.GetSwitchName()})
	}

	if err := mgr.EnablePort(ctx, enableReq.GetPortName()); err != nil {
		h.logger.Error(err, "failed to enable switch port",
			"switch", enableReq.GetSwitchName(), "port", enableReq.GetPortName())
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "SwitchEnablePort", Cause: err})
	}

	resp := &platformv1.EnableSwitchPortResponse{
		Status: &platformv1.Status{Success: true, Message: "port enabled successfully"},
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("enabled switch port",
		"switch", enableReq.GetSwitchName(), "port", enableReq.GetPortName())

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleSwitchDisablePort handles the disable port sub-operation.
func (h *QUICServiceHandler) handleSwitchDisablePort(ctx context.Context, req *quic.Request) *quic.Response {
	var disableReq platformv1.DisableSwitchPortRequest
	if err := quic.DecodePayload(req.Payload, &disableReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if disableReq.GetSwitchName() == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "switch_name"})
	}
	if disableReq.GetPortName() == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "port_name"})
	}

	mgr, err := h.switchService.Manager(disableReq.GetSwitchName())
	if err != nil {
		return h.errorResponse(quic.StatusNotFound, ErrSwitchNotFoundQUIC{Name: disableReq.GetSwitchName()})
	}

	if err := mgr.DisablePort(ctx, disableReq.GetPortName()); err != nil {
		h.logger.Error(err, "failed to disable switch port",
			"switch", disableReq.GetSwitchName(), "port", disableReq.GetPortName())
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "SwitchDisablePort", Cause: err})
	}

	resp := &platformv1.DisableSwitchPortResponse{
		Status: &platformv1.Status{Success: true, Message: "port disabled successfully"},
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("disabled switch port",
		"switch", disableReq.GetSwitchName(), "port", disableReq.GetPortName())

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// Conversion Helpers
// =============================================================================

// portStatusToPb converts a switchmgmt.PortStatus to the platform.v1
// SwitchPortStatus wire message. The native AccessVLAN/TrunkVLANs are uint16;
// the protobuf carries them as uint32 (access_vlan / trunk_vlans).
func portStatusToPb(ps *switchmgmt.PortStatus) *platformv1.SwitchPortStatus {
	if ps == nil {
		return nil
	}

	trunkVLANs := make([]uint32, len(ps.TrunkVLANs))
	for i, v := range ps.TrunkVLANs {
		trunkVLANs[i] = uint32(v)
	}

	return &platformv1.SwitchPortStatus{
		Port:        ps.Port,
		Mode:        string(ps.Mode),
		AccessVlan:  uint32(ps.AccessVLAN),
		TrunkVlans:  trunkVLANs,
		Enabled:     ps.Enabled,
		LinkUp:      ps.LinkUp,
		Description: ps.Description,
		NativeVlan:  uint32(ps.NativeVLAN),
	}
}

// =============================================================================
// Switch-specific Error Types
// =============================================================================

// ErrSwitchNotFoundQUIC is returned when a switch is not found.
type ErrSwitchNotFoundQUIC struct {
	Name string
}

func (e ErrSwitchNotFoundQUIC) Error() string {
	return "switch not found: " + e.Name
}

// ErrSwitchInvalidVLANID is returned when a VLAN ID is out of range.
type ErrSwitchInvalidVLANID struct {
	Value uint32
}

func (e ErrSwitchInvalidVLANID) Error() string {
	return "invalid vlan_id: must be between 1 and 4094"
}
