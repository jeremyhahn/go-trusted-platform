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
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// Overlay pagination defaults
const (
	overlayDefaultLimit int32 = 100
	overlayMaxLimit     int32 = 1000
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

	// ErrOverlayInvalidMAC is returned when an invalid MAC address is specified.
	ErrOverlayInvalidMAC = errors.New("invalid MAC address format")
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

	// MAC table operations
	ListMACs(ctx context.Context, vni uint32) ([]*MACEntry, error)
	ForgetMAC(ctx context.Context, vni uint32, mac string) error
}

// OverlayStatusInfo contains overlay network status information
type OverlayStatusInfo struct {
	Enabled      bool   `codec:"enabled"`
	NodeID       string `codec:"node_id,omitempty"`
	Mode         string `codec:"mode"`
	LocalVTEP    string `codec:"local_vtep"`
	VXLANPort    uint16 `codec:"vxlan_port,omitempty"`
	VTEPCount    int    `codec:"vtep_count"`
	VNICount     int    `codec:"vni_count"`
	TunnelCount  int    `codec:"tunnel_count"`
	MACCount     int    `codec:"mac_count"`
	UplinkIface  string `codec:"uplink_iface,omitempty"`
	MTU          int    `codec:"mtu"`
	EncapType    string `codec:"encap_type"`
	HealthStatus string `codec:"health_status"`
}

// VTEPInfo contains VTEP information
type VTEPInfo struct {
	ID           string   `codec:"id"`
	IPAddress    string   `codec:"ip_address"`
	Hostname     string   `codec:"hostname,omitempty"`
	Status       string   `codec:"status"`
	VNIs         []uint32 `codec:"vnis,omitempty"`
	TunnelCount  int      `codec:"tunnel_count"`
	LastSeen     int64    `codec:"last_seen"`
	Version      string   `codec:"version,omitempty"`
	Capabilities []string `codec:"capabilities,omitempty"`
}

// VNIInfo contains VNI information
type VNIInfo struct {
	VNI         uint32            `codec:"vni"`
	Name        string            `codec:"name,omitempty"`
	BridgeName  string            `codec:"bridge_name,omitempty"`
	Status      string            `codec:"status"`
	MTU         int               `codec:"mtu"`
	MACCount    int               `codec:"mac_count"`
	VTEPCount   int               `codec:"vtep_count"`
	Multicast   string            `codec:"multicast,omitempty"`
	Learning    bool              `codec:"learning"`
	ARPProxy    bool              `codec:"arp_proxy"`
	Labels      map[string]string `codec:"labels,omitempty"`
	CreatedAt   int64             `codec:"created_at"`
	TenantID    string            `codec:"tenant_id,omitempty"`
	NetworkCIDR string            `codec:"network_cidr,omitempty"`
}

// VNICreateOptions contains options for creating a VNI
type VNICreateOptions struct {
	Name        string            `codec:"name,omitempty"`
	MTU         int               `codec:"mtu,omitempty"`
	Multicast   string            `codec:"multicast,omitempty"`
	Learning    bool              `codec:"learning"`
	ARPProxy    bool              `codec:"arp_proxy"`
	Labels      map[string]string `codec:"labels,omitempty"`
	TenantID    string            `codec:"tenant_id,omitempty"`
	NetworkCIDR string            `codec:"network_cidr,omitempty"`
}

// TunnelInfo contains tunnel information
type TunnelInfo struct {
	ID         string `codec:"id"`
	LocalVTEP  string `codec:"local_vtep"`
	RemoteVTEP string `codec:"remote_vtep"`
	VNI        uint32 `codec:"vni"`
	Status     string `codec:"status"`
	EncapType  string `codec:"encap_type"`
	TxBytes    int64  `codec:"tx_bytes"`
	RxBytes    int64  `codec:"rx_bytes"`
	TxPackets  int64  `codec:"tx_packets"`
	RxPackets  int64  `codec:"rx_packets"`
	CreatedAt  int64  `codec:"created_at"`
	LastActive int64  `codec:"last_active"`
}

// MACEntry contains MAC table entry information
type MACEntry struct {
	MAC         string `codec:"mac"`
	VNI         uint32 `codec:"vni"`
	VTEP        string `codec:"vtep"`
	Port        string `codec:"port,omitempty"`
	Type        string `codec:"type"` // static, dynamic, learned
	VLAN        int    `codec:"vlan,omitempty"`
	Age         int    `codec:"age"`
	LastSeen    int64  `codec:"last_seen"`
	IsPermanent bool   `codec:"is_permanent"`
}

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

// OverlayStatusRequest represents a status request
type OverlayStatusRequest struct{}

// OverlayStatusResponse represents a status response
type OverlayStatusResponse struct {
	Status    *OverlayStatusInfo `codec:"status"`
	Timestamp int64              `codec:"timestamp"`
}

// OverlayListVTEPsRequest represents a VTEP list request
type OverlayListVTEPsRequest struct {
	Limit int32 `codec:"limit,omitempty"`
}

// OverlayListVTEPsResponse represents a VTEP list response
type OverlayListVTEPsResponse struct {
	VTEPs     []*VTEPInfo `codec:"vteps"`
	Count     int32       `codec:"count"`
	Timestamp int64       `codec:"timestamp"`
}

// OverlayGetVTEPRequest represents a VTEP get request
type OverlayGetVTEPRequest struct {
	ID string `codec:"id"`
}

// OverlayGetVTEPResponse represents a VTEP get response
type OverlayGetVTEPResponse struct {
	VTEP      *VTEPInfo `codec:"vtep"`
	Timestamp int64     `codec:"timestamp"`
}

// OverlayListVNIsRequest represents a VNI list request
type OverlayListVNIsRequest struct {
	Limit int32 `codec:"limit,omitempty"`
}

// OverlayListVNIsResponse represents a VNI list response
type OverlayListVNIsResponse struct {
	VNIs      []*VNIInfo `codec:"vnis"`
	Count     int32      `codec:"count"`
	Timestamp int64      `codec:"timestamp"`
}

// OverlayCreateVNIRequest represents a VNI creation request
type OverlayCreateVNIRequest struct {
	VNI         uint32            `codec:"vni"`
	Name        string            `codec:"name,omitempty"`
	MTU         int               `codec:"mtu,omitempty"`
	Multicast   string            `codec:"multicast,omitempty"`
	Learning    bool              `codec:"learning"`
	ARPProxy    bool              `codec:"arp_proxy"`
	Labels      map[string]string `codec:"labels,omitempty"`
	TenantID    string            `codec:"tenant_id,omitempty"`
	NetworkCIDR string            `codec:"network_cidr,omitempty"`
}

// OverlayCreateVNIResponse represents a VNI creation response
type OverlayCreateVNIResponse struct {
	VNI       *VNIInfo `codec:"vni"`
	Timestamp int64    `codec:"timestamp"`
}

// OverlayDeleteVNIRequest represents a VNI deletion request
type OverlayDeleteVNIRequest struct {
	VNI uint32 `codec:"vni"`
}

// OverlayDeleteVNIResponse represents a VNI deletion response
type OverlayDeleteVNIResponse struct {
	VNI       uint32 `codec:"vni"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// OverlayListTunnelsRequest represents a tunnel list request
type OverlayListTunnelsRequest struct {
	Limit int32 `codec:"limit,omitempty"`
}

// OverlayListTunnelsResponse represents a tunnel list response
type OverlayListTunnelsResponse struct {
	Tunnels   []*TunnelInfo `codec:"tunnels"`
	Count     int32         `codec:"count"`
	Timestamp int64         `codec:"timestamp"`
}

// OverlayListMACsRequest represents a MAC list request
type OverlayListMACsRequest struct {
	VNI   uint32 `codec:"vni"`
	Limit int32  `codec:"limit,omitempty"`
}

// OverlayListMACsResponse represents a MAC list response
type OverlayListMACsResponse struct {
	MACs      []*MACEntry `codec:"macs"`
	Count     int32       `codec:"count"`
	Timestamp int64       `codec:"timestamp"`
}

// OverlayForgetMACRequest represents a MAC forget request
type OverlayForgetMACRequest struct {
	VNI uint32 `codec:"vni"`
	MAC string `codec:"mac"`
}

// OverlayForgetMACResponse represents a MAC forget response
type OverlayForgetMACResponse struct {
	VNI       uint32 `codec:"vni"`
	MAC       string `codec:"mac"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

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

	// Apply limit
	limit := listReq.Limit
	if limit <= 0 {
		limit = overlayDefaultLimit
	} else if limit > overlayMaxLimit {
		limit = overlayMaxLimit
	}

	if int32(len(vteps)) > limit {
		vteps = vteps[:limit]
	}

	resp := &OverlayListVTEPsResponse{
		VTEPs:     vteps,
		Count:     int32(len(vteps)),
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

	// Apply limit
	limit := listReq.Limit
	if limit <= 0 {
		limit = overlayDefaultLimit
	} else if limit > overlayMaxLimit {
		limit = overlayMaxLimit
	}

	if int32(len(vnis)) > limit {
		vnis = vnis[:limit]
	}

	resp := &OverlayListVNIsResponse{
		VNIs:      vnis,
		Count:     int32(len(vnis)),
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

	opts := &VNICreateOptions{
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

	// Apply limit
	limit := listReq.Limit
	if limit <= 0 {
		limit = overlayDefaultLimit
	} else if limit > overlayMaxLimit {
		limit = overlayMaxLimit
	}

	if int32(len(tunnels)) > limit {
		tunnels = tunnels[:limit]
	}

	resp := &OverlayListTunnelsResponse{
		Tunnels:   tunnels,
		Count:     int32(len(tunnels)),
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

	// Apply limit
	limit := listReq.Limit
	if limit <= 0 {
		limit = overlayDefaultLimit
	} else if limit > overlayMaxLimit {
		limit = overlayMaxLimit
	}

	if int32(len(macs)) > limit {
		macs = macs[:limit]
	}

	resp := &OverlayListMACsResponse{
		MACs:      macs,
		Count:     int32(len(macs)),
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
	case errors.Is(err, ErrOverlayVNIAlreadyExists):
		status = quicwire.StatusAlreadyExists
	case errors.Is(err, ErrOverlayInvalidVNI):
		status = quicwire.StatusInvalidArgument
	case errors.Is(err, ErrOverlayInvalidMAC):
		status = quicwire.StatusInvalidArgument
	case errors.Is(err, ErrOverlayMissingVTEPID):
		status = quicwire.StatusInvalidArgument
	case errors.Is(err, ErrOverlayMissingVNI):
		status = quicwire.StatusInvalidArgument
	case errors.Is(err, ErrOverlayMissingMAC):
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
