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

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/overlay"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// Overlay sentinel errors
var (
	// ErrOverlayServiceNotAvailable is returned when the overlay service is not
	// configured or unavailable.
	ErrOverlayServiceNotAvailable = errors.New("overlay service not available")

	// ErrOverlayMissingVTEPID is returned when a VTEP ID is required but
	// not provided.
	ErrOverlayMissingVTEPID = errors.New("VTEP ID is required")

	// ErrOverlayMissingVNI is returned when a VNI is required but not provided.
	ErrOverlayMissingVNI = errors.New("VNI is required")

	// ErrOverlayMissingMAC is returned when a MAC address is required but
	// not provided.
	ErrOverlayMissingMAC = errors.New("MAC address is required")

	// ErrOverlayVTEPNotFound is returned when a requested VTEP does not exist.
	ErrOverlayVTEPNotFound = errors.New("VTEP not found")

	// ErrOverlayVNINotFound is returned when a requested VNI does not exist.
	ErrOverlayVNINotFound = errors.New("VNI not found")

	// ErrOverlayVNIAlreadyExists is returned when attempting to create a VNI
	// that already exists.
	ErrOverlayVNIAlreadyExists = errors.New("VNI already exists")

	// ErrOverlayMACNotFound is returned when a requested MAC is not found.
	ErrOverlayMACNotFound = errors.New("MAC address not found")

	// ErrOverlayInvalidVNI is returned when an invalid VNI is specified.
	ErrOverlayInvalidVNI = errors.New("invalid VNI: must be between 1 and 16777215")

	// ErrOverlayInvalidVLAN is returned when a VNI's VLAN is above 4094.
	ErrOverlayInvalidVLAN = errors.New("invalid VLAN: must be between 0 and 4094")

	// ErrOverlayInvalidMAC is returned when an invalid MAC address is specified.
	ErrOverlayInvalidMAC = errors.New("invalid MAC address format")

	// ErrOverlayMissingRemoteVTEP is returned when a remote VTEP address is
	// required but not provided.
	ErrOverlayMissingRemoteVTEP = errors.New("remote VTEP address is required")

	// ErrOverlayInvalidRemoteVTEP is returned when a remote VTEP is not an
	// IP address.
	ErrOverlayInvalidRemoteVTEP = errors.New("invalid remote VTEP address")

	// ErrOverlayTunnelNotFound is returned when no tunnel matches a query.
	ErrOverlayTunnelNotFound = errors.New("tunnel not found")
)

// OverlayServiceInterface defines the interface for overlay network operations.
type OverlayServiceInterface interface {
	// Status returns the current overlay network status
	Status(ctx context.Context) (*OverlayStatusInfo, error)

	// VTEP operations
	ListVTEPs(ctx context.Context) ([]*VTEPInfo, error)
	GetVTEP(ctx context.Context, id string) (*VTEPInfo, error)

	// VNI operations
	ListVNIs(ctx context.Context) ([]*VNIInfo, error)
	CreateVNI(ctx context.Context, vni uint32, opts *VNICreateOptions) (*VNIInfo, error)
	DeleteVNI(ctx context.Context, vni uint32) error

	// Tunnel operations
	ListTunnels(ctx context.Context) ([]*TunnelInfo, error)
	// TunnelStats returns the tunnel to remoteVTEP carrying vni (any VNI
	// when vni is 0) with its counters.
	TunnelStats(ctx context.Context, remoteVTEP string, vni uint32) (*TunnelInfo, error)

	// MAC table operations
	ListMACs(ctx context.Context, vni uint32) ([]*MACEntry, error)
	ForgetMAC(ctx context.Context, vni uint32, mac string) error
}

// Overlay wire shapes live in quicwire so the SDK adapter decodes the same
// structs this handler encodes.
type (
	OverlayStatusInfo = quicwire.OverlayStatusInfo
	VTEPInfo          = quicwire.VTEPInfo
	VNIInfo           = quicwire.VNIInfo
	VNICreateOptions  = quicwire.VNICreateOptions
	TunnelInfo        = quicwire.TunnelInfo
	MACEntry          = quicwire.MACEntry

	OverlayStatusRequest       = quicwire.OverlayStatusRequest
	OverlayStatusResponse      = quicwire.OverlayStatusResponse
	OverlayListVTEPsRequest    = quicwire.OverlayListVTEPsRequest
	OverlayListVTEPsResponse   = quicwire.OverlayListVTEPsResponse
	OverlayGetVTEPRequest      = quicwire.OverlayGetVTEPRequest
	OverlayGetVTEPResponse     = quicwire.OverlayGetVTEPResponse
	OverlayListVNIsRequest     = quicwire.OverlayListVNIsRequest
	OverlayListVNIsResponse    = quicwire.OverlayListVNIsResponse
	OverlayCreateVNIRequest    = quicwire.OverlayCreateVNIRequest
	OverlayCreateVNIResponse   = quicwire.OverlayCreateVNIResponse
	OverlayDeleteVNIRequest    = quicwire.OverlayDeleteVNIRequest
	OverlayDeleteVNIResponse   = quicwire.OverlayDeleteVNIResponse
	OverlayListTunnelsRequest  = quicwire.OverlayListTunnelsRequest
	OverlayListTunnelsResponse = quicwire.OverlayListTunnelsResponse
	OverlayTunnelStatsRequest  = quicwire.OverlayTunnelStatsRequest
	OverlayTunnelStatsResponse = quicwire.OverlayTunnelStatsResponse
	OverlayListMACsRequest     = quicwire.OverlayListMACsRequest
	OverlayListMACsResponse    = quicwire.OverlayListMACsResponse
	OverlayForgetMACRequest    = quicwire.OverlayForgetMACRequest
	OverlayForgetMACResponse   = quicwire.OverlayForgetMACResponse
)

// OverlayHandler handles overlay network operations over QUIC
type OverlayHandler struct {
	overlayService OverlayServiceInterface
	logger         *logging.Logger
}

// NewOverlayHandler creates a new overlay handler
func NewOverlayHandler(logger *logging.Logger, overlayService OverlayServiceInterface) *OverlayHandler {
	return &OverlayHandler{
		overlayService: overlayService,
		logger:         logger,
	}
}

// HandleRequest processes an overlay request and returns a response.
// This handler expects extended opcodes with the overlay category marker.
func (h *OverlayHandler) HandleRequest(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if req == nil {
		return &quicwire.Response{
			Status:  quicwire.StatusInvalidRequest,
			Payload: []byte(quicwire.ErrNilRequest.Error()),
		}
	}

	switch req.Opcode {
	case quicwire.OpOverlayStatus:
		return h.handleStatus(ctx, req)
	case quicwire.OpOverlayListVTEPs:
		return h.handleListVTEPs(ctx, req)
	case quicwire.OpOverlayGetVTEP:
		return h.handleGetVTEP(ctx, req)
	case quicwire.OpOverlayListVNIs:
		return h.handleListVNIs(ctx, req)
	case quicwire.OpOverlayCreateVNI:
		return h.handleCreateVNI(ctx, req)
	case quicwire.OpOverlayDeleteVNI:
		return h.handleDeleteVNI(ctx, req)
	case quicwire.OpOverlayListTunns:
		return h.handleListTunnels(ctx, req)
	case quicwire.OpOverlayTunnelStats:
		return h.handleTunnelStats(ctx, req)
	case quicwire.OpOverlayListMACs:
		return h.handleListMACs(ctx, req)
	case quicwire.OpOverlayForgetMAC:
		return h.handleForgetMAC(ctx, req)
	default:
		return &quicwire.Response{
			Status:  quicwire.StatusInvalidRequest,
			Payload: []byte("unknown overlay operation"),
		}
	}
}

// =============================================================================
// Request/Response Types
// =============================================================================

// =============================================================================
// Handler Methods
// =============================================================================

// handleStatus returns the overlay network status
func (h *OverlayHandler) handleStatus(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.overlayService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrOverlayServiceNotAvailable)
	}

	status, err := h.overlayService.Status(ctx)
	if err != nil {
		h.logger.Error(err, "failed to get overlay status")
		return h.overlayErrorResponse(err)
	}

	resp := &OverlayStatusResponse{
		Status:    status,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrOverlayEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleListVTEPs lists all VTEPs
func (h *OverlayHandler) handleListVTEPs(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.overlayService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrOverlayServiceNotAvailable)
	}

	var listReq OverlayListVTEPsRequest
	if err := quicwire.DecodePayload(req.Payload, &listReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrOverlayDecodingFailed{Cause: err})
	}

	vteps, err := h.overlayService.ListVTEPs(ctx)
	if err != nil {
		h.logger.Error(err, "failed to list VTEPs")
		return h.overlayErrorResponse(err)
	}

	page, total, err := listPage(vteps, listReq.Offset, listReq.Limit)
	if err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, err)
	}

	resp := &OverlayListVTEPsResponse{
		VTEPs:     page,
		Count:     int32(len(page)),
		Total:     total,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrOverlayEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleGetVTEP gets a VTEP by ID
func (h *OverlayHandler) handleGetVTEP(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.overlayService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrOverlayServiceNotAvailable)
	}

	var getReq OverlayGetVTEPRequest
	if err := quicwire.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrOverlayDecodingFailed{Cause: err})
	}

	if getReq.ID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrOverlayMissingVTEPID)
	}

	vtep, err := h.overlayService.GetVTEP(ctx, getReq.ID)
	if err != nil {
		h.logger.Error(err, "failed to get VTEP")
		return h.overlayErrorResponse(err)
	}

	resp := &OverlayGetVTEPResponse{
		VTEP:      vtep,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrOverlayEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleListVNIs lists all VNIs
func (h *OverlayHandler) handleListVNIs(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.overlayService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrOverlayServiceNotAvailable)
	}

	var listReq OverlayListVNIsRequest
	if err := quicwire.DecodePayload(req.Payload, &listReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrOverlayDecodingFailed{Cause: err})
	}

	vnis, err := h.overlayService.ListVNIs(ctx)
	if err != nil {
		h.logger.Error(err, "failed to list VNIs")
		return h.overlayErrorResponse(err)
	}

	page, total, err := listPage(vnis, listReq.Offset, listReq.Limit)
	if err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, err)
	}

	resp := &OverlayListVNIsResponse{
		VNIs:      page,
		Count:     int32(len(page)),
		Total:     total,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrOverlayEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleCreateVNI creates a new VNI
func (h *OverlayHandler) handleCreateVNI(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.overlayService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrOverlayServiceNotAvailable)
	}

	var createReq OverlayCreateVNIRequest
	if err := quicwire.DecodePayload(req.Payload, &createReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrOverlayDecodingFailed{Cause: err})
	}

	if createReq.VNI == 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrOverlayMissingVNI)
	}

	// Validate VNI range (1 to 16777215 for VXLAN)
	if createReq.VNI > 16777215 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrOverlayInvalidVNI)
	}

	if createReq.VLAN > overlay.MaxVLAN {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrOverlayInvalidVLAN)
	}

	opts := &VNICreateOptions{
		VLAN:        createReq.VLAN,
		Name:        createReq.Name,
		MTU:         createReq.MTU,
		Multicast:   createReq.Multicast,
		Learning:    createReq.Learning,
		ARPProxy:    createReq.ARPProxy,
		Labels:      createReq.Labels,
		TenantID:    createReq.TenantID,
		NetworkCIDR: createReq.NetworkCIDR,
	}

	vni, err := h.overlayService.CreateVNI(ctx, createReq.VNI, opts)
	if err != nil {
		h.logger.Error(err, "failed to create VNI")
		return h.overlayErrorResponse(err)
	}

	resp := &OverlayCreateVNIResponse{
		VNI:       vni,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrOverlayEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleDeleteVNI deletes a VNI
func (h *OverlayHandler) handleDeleteVNI(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.overlayService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrOverlayServiceNotAvailable)
	}

	var deleteReq OverlayDeleteVNIRequest
	if err := quicwire.DecodePayload(req.Payload, &deleteReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrOverlayDecodingFailed{Cause: err})
	}

	if deleteReq.VNI == 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrOverlayMissingVNI)
	}

	if err := h.overlayService.DeleteVNI(ctx, deleteReq.VNI); err != nil {
		h.logger.Error(err, "failed to delete VNI")
		return h.overlayErrorResponse(err)
	}

	resp := &OverlayDeleteVNIResponse{
		VNI:       deleteReq.VNI,
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrOverlayEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleListTunnels lists all tunnels
func (h *OverlayHandler) handleListTunnels(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.overlayService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrOverlayServiceNotAvailable)
	}

	var listReq OverlayListTunnelsRequest
	if err := quicwire.DecodePayload(req.Payload, &listReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrOverlayDecodingFailed{Cause: err})
	}

	tunnels, err := h.overlayService.ListTunnels(ctx)
	if err != nil {
		h.logger.Error(err, "failed to list tunnels")
		return h.overlayErrorResponse(err)
	}

	if listReq.VNI != 0 {
		tunnels = tunnelsForVNI(tunnels, listReq.VNI)
	}

	page, total, err := listPage(tunnels, listReq.Offset, listReq.Limit)
	if err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, err)
	}

	resp := &OverlayListTunnelsResponse{
		Tunnels:   page,
		Count:     int32(len(page)),
		Total:     total,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrOverlayEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// tunnelsForVNI returns the tunnels carrying vni, as gRPC ListTunnels
// filters them.
func tunnelsForVNI(tunnels []*TunnelInfo, vni uint32) []*TunnelInfo {
	matched := make([]*TunnelInfo, 0, len(tunnels))
	for _, tunnel := range tunnels {
		if tunnel != nil && tunnel.VNI == vni {
			matched = append(matched, tunnel)
		}
	}
	return matched
}

// handleTunnelStats returns one tunnel's counters, as gRPC GetTunnelStats does.
func (h *OverlayHandler) handleTunnelStats(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.overlayService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrOverlayServiceNotAvailable)
	}

	var statsReq OverlayTunnelStatsRequest
	if err := quicwire.DecodePayload(req.Payload, &statsReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrOverlayDecodingFailed{Cause: err})
	}

	if statsReq.RemoteVTEP == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrOverlayMissingRemoteVTEP)
	}

	tunnel, err := h.overlayService.TunnelStats(ctx, statsReq.RemoteVTEP, statsReq.VNI)
	if err != nil {
		h.logger.Error(err, "failed to get tunnel statistics")
		return h.overlayErrorResponse(err)
	}

	resp := &OverlayTunnelStatsResponse{
		Tunnel:    tunnel,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrOverlayEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleListMACs lists MAC entries for a VNI
func (h *OverlayHandler) handleListMACs(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.overlayService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrOverlayServiceNotAvailable)
	}

	var listReq OverlayListMACsRequest
	if err := quicwire.DecodePayload(req.Payload, &listReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrOverlayDecodingFailed{Cause: err})
	}

	// VNI == 0 means list all MACs (same semantics as gRPC ListRemoteMACs).
	macs, err := h.overlayService.ListMACs(ctx, listReq.VNI)
	if err != nil {
		h.logger.Error(err, "failed to list MACs")
		return h.overlayErrorResponse(err)
	}

	page, total, err := listPage(macs, listReq.Offset, listReq.Limit)
	if err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, err)
	}

	resp := &OverlayListMACsResponse{
		MACs:      page,
		Count:     int32(len(page)),
		Total:     total,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrOverlayEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleForgetMAC removes a MAC entry from the table
func (h *OverlayHandler) handleForgetMAC(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.overlayService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrOverlayServiceNotAvailable)
	}

	var forgetReq OverlayForgetMACRequest
	if err := quicwire.DecodePayload(req.Payload, &forgetReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrOverlayDecodingFailed{Cause: err})
	}

	if forgetReq.VNI == 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrOverlayMissingVNI)
	}

	if forgetReq.MAC == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrOverlayMissingMAC)
	}

	// Validate MAC address format
	if _, err := net.ParseMAC(forgetReq.MAC); err != nil {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrOverlayInvalidMAC)
	}

	if err := h.overlayService.ForgetMAC(ctx, forgetReq.VNI, forgetReq.MAC); err != nil {
		h.logger.Error(err, "failed to forget MAC")
		return h.overlayErrorResponse(err)
	}

	resp := &OverlayForgetMACResponse{
		VNI:       forgetReq.VNI,
		MAC:       forgetReq.MAC,
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrOverlayEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// Helper Methods
// =============================================================================

// errorResponse creates an error response with the given status and error
func (h *OverlayHandler) errorResponse(status byte, err error) *quicwire.Response {
	return &quicwire.Response{
		Status:  status,
		Payload: []byte(err.Error()),
	}
}

// overlayErrorResponse maps overlay errors to appropriate status codes
func (h *OverlayHandler) overlayErrorResponse(err error) *quicwire.Response {
	var status byte

	switch {
	case errors.Is(err, ErrOverlayVTEPNotFound):
		status = quicwire.StatusNotFound
	case errors.Is(err, ErrOverlayVNINotFound):
		status = quicwire.StatusNotFound
	case errors.Is(err, ErrOverlayMACNotFound):
		status = quicwire.StatusNotFound
	case errors.Is(err, ErrOverlayTunnelNotFound):
		status = quicwire.StatusNotFound
	case errors.Is(err, ErrOverlayVNIAlreadyExists):
		status = quicwire.StatusAlreadyExists
	case errors.Is(err, ErrOverlayInvalidVNI):
		status = quicwire.StatusInvalidArgument
	case errors.Is(err, ErrOverlayInvalidVLAN):
		status = quicwire.StatusInvalidArgument
	case errors.Is(err, ErrOverlayInvalidMAC):
		status = quicwire.StatusInvalidArgument
	case errors.Is(err, ErrOverlayMissingVTEPID):
		status = quicwire.StatusInvalidArgument
	case errors.Is(err, ErrOverlayMissingVNI):
		status = quicwire.StatusInvalidArgument
	case errors.Is(err, ErrOverlayMissingMAC):
		status = quicwire.StatusInvalidArgument
	case errors.Is(err, ErrOverlayMissingRemoteVTEP):
		status = quicwire.StatusInvalidArgument
	case errors.Is(err, ErrOverlayInvalidRemoteVTEP):
		status = quicwire.StatusInvalidArgument
	case errors.Is(err, ErrOverlayServiceNotAvailable):
		status = quicwire.StatusUnavailable
	default:
		status = quicwire.StatusInternalError
	}

	return h.errorResponse(status, err)
}

// =============================================================================
// Overlay Error Types
// =============================================================================

// ErrOverlayEncodingFailed represents an encoding failure error
type ErrOverlayEncodingFailed struct {
	Cause error
}

func (e ErrOverlayEncodingFailed) Error() string {
	return "failed to encode overlay payload: " + e.Cause.Error()
}

func (e ErrOverlayEncodingFailed) Unwrap() error {
	return e.Cause
}

// ErrOverlayDecodingFailed represents a decoding failure error
type ErrOverlayDecodingFailed struct {
	Cause error
}

func (e ErrOverlayDecodingFailed) Error() string {
	return "failed to decode overlay payload: " + e.Cause.Error()
}

func (e ErrOverlayDecodingFailed) Unwrap() error {
	return e.Cause
}

// ErrOverlayOperationFailed represents an overlay operation failure
type ErrOverlayOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrOverlayOperationFailed) Error() string {
	return "overlay operation " + e.Operation + " failed: " + e.Cause.Error()
}

func (e ErrOverlayOperationFailed) Unwrap() error {
	return e.Cause
}
