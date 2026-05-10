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
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	switchmgmt "github.com/jeremyhahn/go-trusted-platform/pkg/switch"
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
// Request/Response Types
// =============================================================================

// SwitchListPortsRequest represents a request to list all ports on a switch.
type SwitchListPortsRequest struct {
	SwitchName string `codec:"switch_name"`
}

// SwitchPortStatusWire holds the observable state of a single switch port for QUIC.
type SwitchPortStatusWire struct {
	Port        string   `codec:"port"`
	Mode        string   `codec:"mode"`
	AccessVLAN  uint16   `codec:"access_vlan"`
	TrunkVLANs  []uint16 `codec:"trunk_vlans,omitempty"`
	Enabled     bool     `codec:"enabled"`
	LinkUp      bool     `codec:"link_up"`
	Description string   `codec:"description,omitempty"`
}

// SwitchListPortsResponse represents a response containing port statuses.
type SwitchListPortsResponse struct {
	Ports     []*SwitchPortStatusWire `codec:"ports"`
	Timestamp int64                   `codec:"timestamp"`
}

// SwitchGetPortStatusRequest represents a request to get a single port's status.
type SwitchGetPortStatusRequest struct {
	SwitchName string `codec:"switch_name"`
	PortName   string `codec:"port_name"`
}

// SwitchGetPortStatusResponse represents a response containing a single port's status.
type SwitchGetPortStatusResponse struct {
	Port      *SwitchPortStatusWire `codec:"port"`
	Timestamp int64                 `codec:"timestamp"`
}

// SwitchSetPortVLANRequest represents a request to set a port's VLAN.
type SwitchSetPortVLANRequest struct {
	SwitchName string `codec:"switch_name"`
	PortName   string `codec:"port_name"`
	VLANID     uint16 `codec:"vlan_id"`
}

// SwitchSetPortVLANResponse represents a response after setting a port's VLAN.
type SwitchSetPortVLANResponse struct {
	Success   bool   `codec:"success"`
	Message   string `codec:"message,omitempty"`
	Timestamp int64  `codec:"timestamp"`
}

// SwitchEnablePortRequest represents a request to enable a port.
type SwitchEnablePortRequest struct {
	SwitchName string `codec:"switch_name"`
	PortName   string `codec:"port_name"`
}

// SwitchEnablePortResponse represents a response after enabling a port.
type SwitchEnablePortResponse struct {
	Success   bool   `codec:"success"`
	Message   string `codec:"message,omitempty"`
	Timestamp int64  `codec:"timestamp"`
}

// SwitchDisablePortRequest represents a request to disable a port.
type SwitchDisablePortRequest struct {
	SwitchName string `codec:"switch_name"`
	PortName   string `codec:"port_name"`
}

// SwitchDisablePortResponse represents a response after disabling a port.
type SwitchDisablePortResponse struct {
	Success   bool   `codec:"success"`
	Message   string `codec:"message,omitempty"`
	Timestamp int64  `codec:"timestamp"`
}

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
	var listReq SwitchListPortsRequest
	if len(req.Payload) > 0 {
		if err := quic.DecodePayload(req.Payload, &listReq); err != nil {
			return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
		}
	}

	if listReq.SwitchName == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "switch_name"})
	}

	mgr, err := h.switchService.Manager(listReq.SwitchName)
	if err != nil {
		return h.errorResponse(quic.StatusNotFound, ErrSwitchNotFoundQUIC{Name: listReq.SwitchName})
	}

	ports, err := mgr.ListPorts(ctx)
	if err != nil {
		h.logger.Error(err, "failed to list switch ports", "switch", listReq.SwitchName)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "SwitchListPorts", Cause: err})
	}

	wirePorts := make([]*SwitchPortStatusWire, 0, len(ports))
	for _, p := range ports {
		wirePorts = append(wirePorts, portStatusToWire(p))
	}

	resp := &SwitchListPortsResponse{
		Ports:     wirePorts,
		Timestamp: time.Now().Unix(),
	}

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
	var getReq SwitchGetPortStatusRequest
	if err := quic.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if getReq.SwitchName == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "switch_name"})
	}
	if getReq.PortName == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "port_name"})
	}

	mgr, err := h.switchService.Manager(getReq.SwitchName)
	if err != nil {
		return h.errorResponse(quic.StatusNotFound, ErrSwitchNotFoundQUIC{Name: getReq.SwitchName})
	}

	portStatus, err := mgr.GetPortStatus(ctx, getReq.PortName)
	if err != nil {
		h.logger.Error(err, "failed to get switch port status",
			"switch", getReq.SwitchName, "port", getReq.PortName)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "SwitchGetPortStatus", Cause: err})
	}

	resp := &SwitchGetPortStatusResponse{
		Port:      portStatusToWire(portStatus),
		Timestamp: time.Now().Unix(),
	}

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
	var setReq SwitchSetPortVLANRequest
	if err := quic.DecodePayload(req.Payload, &setReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if setReq.SwitchName == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "switch_name"})
	}
	if setReq.PortName == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "port_name"})
	}
	if setReq.VLANID == 0 || setReq.VLANID > 4094 {
		return h.errorResponse(quic.StatusInvalidArgument, ErrSwitchInvalidVLANID{Value: setReq.VLANID})
	}

	mgr, err := h.switchService.Manager(setReq.SwitchName)
	if err != nil {
		return h.errorResponse(quic.StatusNotFound, ErrSwitchNotFoundQUIC{Name: setReq.SwitchName})
	}

	if err := mgr.SetPortVLAN(ctx, setReq.PortName, setReq.VLANID); err != nil {
		h.logger.Error(err, "failed to set switch port VLAN",
			"switch", setReq.SwitchName, "port", setReq.PortName, "vlan", setReq.VLANID)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "SwitchSetPortVLAN", Cause: err})
	}

	resp := &SwitchSetPortVLANResponse{
		Success:   true,
		Message:   "port VLAN updated successfully",
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("set switch port VLAN",
		"switch", setReq.SwitchName, "port", setReq.PortName, "vlan", setReq.VLANID)

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleSwitchEnablePort handles the enable port sub-operation.
func (h *QUICServiceHandler) handleSwitchEnablePort(ctx context.Context, req *quic.Request) *quic.Response {
	var enableReq SwitchEnablePortRequest
	if err := quic.DecodePayload(req.Payload, &enableReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if enableReq.SwitchName == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "switch_name"})
	}
	if enableReq.PortName == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "port_name"})
	}

	mgr, err := h.switchService.Manager(enableReq.SwitchName)
	if err != nil {
		return h.errorResponse(quic.StatusNotFound, ErrSwitchNotFoundQUIC{Name: enableReq.SwitchName})
	}

	if err := mgr.EnablePort(ctx, enableReq.PortName); err != nil {
		h.logger.Error(err, "failed to enable switch port",
			"switch", enableReq.SwitchName, "port", enableReq.PortName)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "SwitchEnablePort", Cause: err})
	}

	resp := &SwitchEnablePortResponse{
		Success:   true,
		Message:   "port enabled successfully",
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("enabled switch port",
		"switch", enableReq.SwitchName, "port", enableReq.PortName)

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handleSwitchDisablePort handles the disable port sub-operation.
func (h *QUICServiceHandler) handleSwitchDisablePort(ctx context.Context, req *quic.Request) *quic.Response {
	var disableReq SwitchDisablePortRequest
	if err := quic.DecodePayload(req.Payload, &disableReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if disableReq.SwitchName == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "switch_name"})
	}
	if disableReq.PortName == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "port_name"})
	}

	mgr, err := h.switchService.Manager(disableReq.SwitchName)
	if err != nil {
		return h.errorResponse(quic.StatusNotFound, ErrSwitchNotFoundQUIC{Name: disableReq.SwitchName})
	}

	if err := mgr.DisablePort(ctx, disableReq.PortName); err != nil {
		h.logger.Error(err, "failed to disable switch port",
			"switch", disableReq.SwitchName, "port", disableReq.PortName)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "SwitchDisablePort", Cause: err})
	}

	resp := &SwitchDisablePortResponse{
		Success:   true,
		Message:   "port disabled successfully",
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("disabled switch port",
		"switch", disableReq.SwitchName, "port", disableReq.PortName)

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// Conversion Helpers
// =============================================================================

// portStatusToWire converts a switchmgmt.PortStatus to a SwitchPortStatusWire.
func portStatusToWire(ps *switchmgmt.PortStatus) *SwitchPortStatusWire {
	if ps == nil {
		return nil
	}

	trunkVLANs := make([]uint16, len(ps.TrunkVLANs))
	copy(trunkVLANs, ps.TrunkVLANs)

	return &SwitchPortStatusWire{
		Port:        ps.Port,
		Mode:        string(ps.Mode),
		AccessVLAN:  ps.AccessVLAN,
		TrunkVLANs:  trunkVLANs,
		Enabled:     ps.Enabled,
		LinkUp:      ps.LinkUp,
		Description: ps.Description,
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
	Value uint16
}

func (e ErrSwitchInvalidVLANID) Error() string {
	return "invalid vlan_id: must be between 1 and 4094"
}
